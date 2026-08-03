#!/usr/bin/env python3
"""
Kiro DLP 判定薄 HTTP 服务（方案二联动版）

作用：mitmproxy addon 解密 runtime.<region>.kiro.dev 的推理请求后，把明文 body
      POST 到本服务 /inspect；本服务前置 DLPEngine.scan 做同步裁决，返回
      PASS / REDACT / BLOCK。内容全程不出 VPC、绝不发第三方 LLM。

落地形态：纯 stdlib http.server.ThreadingHTTPServer，跑在【复用现有镜像
          kiro-dlp-engine:latest】里（引擎是纯 stdlib，镜像能跑 run_offline 即证明
          解释器 + stdlib 齐全），零新依赖、零镜像重建，合规链路只 load+up。

────────────────────────────────────────────────────────────────────────
★ 已对照【容器内真实源码】校准的关键事实（勿按臆测改回旧假设）：

  1) EngineConfig 真实签名（无 presidio_url / 无 l3_unreachable 参数！）：
       EngineConfig(presidio_languages=('en','zh'), l3_timeout=2.0,
                    run_l3_on_all_variants=True, use_bedrock_l4=False,
                    l4_model_key='main', redact_mask='[REDACTED:{entity}]')
     -> Presidio 地址由引擎从环境变量 PRESIDIO_ANALYZER_URL 读取，
        绝不作为 EngineConfig 关键字参数传入（那样会 TypeError 崩溃）。

  2) DLPEngine.scan(content, *, injection_point=PROMPT, run_async_l4=False,
                    session_window=None) -> ScanResult
     content 可为 dict（引擎 extract 递归展开所有字符串叶子）或 str。

  3) ScanResult 字段：verdict(Verdict枚举 pass/redact/block), hits(list[Hit]),
       top_layer(Layer|None), redacted_text(str|None), async_alerts,
       latency_ms(dict), normalized_variants, notes(list[str])
     - dict 入参时 redacted_text = 对整个输入 JSON 脱敏后的【完整 JSON 串】
       （engine 内部 json.dumps(_redact_obj(deepcopy(content)))），
       结构与原 body 一致 -> addon 可直接当 request body 写回，不破坏 schema。
     - HTTP 契约里把它命名为 redacted_body（与 addon 对齐）。

  4) Hit 字段：layer, rule, entity, span, matched, action, confidence,
       source, field_path
     ★ matched(原始命中的敏感子串) 与 span 绝不能出现在响应/日志里 ——
       只回 layer/rule/entity/field_path/confidence/action。

  5) ★ L3(Presidio) 不可达时引擎【只在 notes 里标注、不强制 BLOCK】
       （见 engine.py：notes.append("L3 skipped(analyzer 不可达)...")）。
       引擎 l3_presidio 的注释写明「fail-closed 责任交给调用方」。
       -> 本服务必须扫 notes，命中「L3 不可达」或「REDACT 未生效」时
          强制升级为 BLOCK，否则就是静默 fail-open 数据外泄通道（规格 D4）。

  6) Verdict 枚举值是小写(pass/redact/block)，本服务对外输出 .name(大写)
     与 addon 的 == "PASS"/"REDACT"/"BLOCK" 比较对齐。

不变量：本服务在【任何错误路径都不返回 PASS】。扫描异常 -> 503（addon 对 503
        恒 fail-closed）；L3 不可达 -> 强制 BLOCK；未知情况 -> 503。
"""

import json
import logging
import os
import queue
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# 引擎包在镜像 /app 下（WORKDIR=/app, PYTHONPATH=/app 已内建），import dlp 已核实 OK。
from dlp.engine import DLPEngine, EngineConfig
from dlp.types import InjectionPoint

# ---------------- 配置（compose environment 注入）----------------
PORT = int(os.environ.get("DLP_HTTP_PORT", "9000"))
BIND = os.environ.get("DLP_HTTP_BIND", "0.0.0.0")  # 容器命名空间内；真正收敛靠 host 私网映射 + SG
MAX_BODY = int(os.environ.get("DLP_MAX_BODY_BYTES", str(16 * 1024 * 1024)))  # 16 MiB
INJ = getattr(InjectionPoint, os.environ.get("DLP_SCAN_INJECTION_POINT", "PROMPT"))
POOL_N = int(os.environ.get("DLP_ENGINE_POOL_SIZE", "4"))
POOL_WAIT = float(os.environ.get("DLP_ENGINE_POOL_WAIT", "10.0"))  # 取引擎最长等待，超则 503
L3_TIMEOUT_S = float(os.environ.get("DLP_PRESIDIO_TIMEOUT_MS", "2000")) / 1000.0
PRESIDIO_LANGS = tuple(
    x.strip() for x in os.environ.get("DLP_PRESIDIO_LANGS", "en,zh").split(",") if x.strip()
)
# L3 不可达 / 覆盖不完整时的动作：block=fail-closed(默认，安全) | keep=保留引擎原判(危险，仅调试)
L3_UNAVAILABLE_ACTION = os.environ.get("DLP_L3_UNAVAILABLE_ACTION", "block").lower()
# ---- L3 大 body 性能补丁(去重+省扫+并发;默认省扫仅 raw/normalized、并发 16)----
RUN_L3_ON_ALL = os.environ.get("DLP_RUN_L3_ON_ALL_VARIANTS", "false").lower() in ("1", "true", "yes")
L3_CONCURRENCY = int(os.environ.get("DLP_L3_CONCURRENCY", "16"))

log = logging.getLogger("dlp-http")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

# ---------------- 引擎对象池（规格 D8：不用全局单锁串行化）----------------
# 用 N 个预构造引擎实例；每个请求独占一个，用完归还。无论 scan 是否线程安全都成立，
# 且并发上限 = POOL_N，形成天然背压（池空则新请求等待 POOL_WAIT，超时回 503 -> addon fail-closed）。
#
# EngineConfig：绝不传 presidio_url（真实签名无此参数）；use_bedrock_l4=False 双保险
# （同步腿红线：永不触 Bedrock/第三方，scan 也显式 run_async_l4=False）。
_CFG = EngineConfig(
    presidio_languages=PRESIDIO_LANGS,
    l3_timeout=L3_TIMEOUT_S,
    use_bedrock_l4=False,
    run_l3_on_all_variants=RUN_L3_ON_ALL,
    l3_concurrency=L3_CONCURRENCY,
)
_pool: "queue.Queue[DLPEngine]" = queue.Queue()
for _ in range(max(1, POOL_N)):
    _pool.put(DLPEngine(_CFG))


def _do_scan(content):
    """从池取引擎跑 scan，用完归还。池空等待 POOL_WAIT，超时抛 queue.Empty -> 上层 503。"""
    eng = _pool.get(timeout=POOL_WAIT)
    try:
        return eng.scan(content, injection_point=INJ, run_async_l4=False)
    finally:
        _pool.put(eng)


# ---------------- fail-closed 升级（规格 D4 核心）----------------
# 引擎把「L3 不可达」只写进 notes 不强制 BLOCK；这里代调用方补齐 fail-closed。
_L3_UNAVAILABLE_MARKERS = ("analyzer 不可达", "部分语言失败", "L3 skipped")
_REDACT_INEFFECTIVE_MARKERS = ("REDACT 未生效",)


def _forced_block_reason(result) -> str:
    notes_txt = " ".join(result.notes or [])
    # REDACT 落空：命中片段不在原文字面，脱敏没生效 -> 敏感内容仍在 -> 必须 BLOCK
    if any(m in notes_txt for m in _REDACT_INEFFECTIVE_MARKERS):
        return "redaction_ineffective"
    # L3 不可达 / 覆盖不完整：可能漏检 PII -> 默认 fail-closed 升级为 BLOCK
    if L3_UNAVAILABLE_ACTION == "block" and any(
        m in notes_txt for m in _L3_UNAVAILABLE_MARKERS
    ):
        return "l3_unavailable"
    return ""


# ---------------- ScanResult -> HTTP JSON（剥离敏感字段）----------------
def _layer_val(layer):
    return getattr(layer, "value", None) if layer is not None else None


def _safe_rules(hits):
    """只输出安全字段；★绝不含 matched(原始敏感子串)/span。"""
    out = []
    for h in hits or []:
        out.append({
            "layer": _layer_val(getattr(h, "layer", None)),
            "rule": getattr(h, "rule", None),
            "entity": getattr(h, "entity", None),
            "field_path": getattr(h, "field_path", None),
            "confidence": getattr(h, "confidence", None),
            "action": _layer_val(getattr(h, "action", None)) or getattr(getattr(h, "action", None), "name", None),
        })
    return out


def _result_to_response(result) -> dict:
    verdict = result.verdict.name if hasattr(result.verdict, "name") else str(result.verdict).upper()

    forced = _forced_block_reason(result)
    if forced:
        # 升级为 BLOCK：丢弃可能不完整的 redacted_text，记明原因。
        body = {
            "verdict": "BLOCK",
            "top_layer": _layer_val(result.top_layer),
            "rules": _safe_rules(result.hits),
            "latency_ms": result.latency_ms or {},
            "notes": (result.notes or []) + [f"forced_block:{forced}"],
            "forced_block": forced,
        }
        return body

    body = {
        "verdict": verdict,
        "top_layer": _layer_val(result.top_layer),
        "rules": _safe_rules(result.hits),
        "latency_ms": result.latency_ms or {},
        "notes": result.notes or [],
    }
    if verdict == "REDACT":
        # dict 入参时 redacted_text 是完整脱敏 JSON 串 -> addon 直接当 body 写回。
        body["redacted_body"] = result.redacted_text
    return body


# ---------------- HTTP handler ----------------
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code: int, obj: dict) -> None:
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except BrokenPipeError:
            pass  # 客户端已断开（如 addon 超时），忽略

    def do_GET(self):  # noqa: N802
        if self.path.split("?")[0] == "/health":
            # 浅存活：只证明进程 + 引擎池就绪，不 ping presidio（避免探针抖动触发重启）。
            self._send(200, {"status": "ok", "engine": "ready", "pool": POOL_N})
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self):  # noqa: N802
        if self.path.split("?")[0] != "/inspect":
            return self._send(404, {"error": "not_found"})

        try:
            n = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError):
            return self._send(400, {"error": "bad_content_length"})
        if n <= 0 or n > MAX_BODY:
            return self._send(413, {"error": "body_too_large_or_empty", "max": MAX_BODY})

        try:
            raw = self.rfile.read(n)
        except Exception:
            return self._send(400, {"error": "read_error"})

        t0 = time.time()
        # server 独占 json.loads：addon 保持「不懂 CodeWhisperer schema」，只传原始 bytes。
        try:
            content = json.loads(raw)  # 通常是 dict -> 引擎递归展开字符串叶子
        except Exception:
            content = raw.decode("utf-8", "replace")  # 非 JSON 兜底为扁平 str，仍走引擎

        try:
            result = _do_scan(content)
        except queue.Empty:
            # 引擎池被占满且等待超时：视为服务不可用 -> 503（addon 恒 fail-closed）。
            log.warning("engine_pool_exhausted wait=%.1fs", POOL_WAIT)
            return self._send(503, {"error": "dlp_busy"})
        except Exception as e:
            # 规格 D13：只记异常类型，绝不记 content / 堆栈原文（会泄敏）。
            log.error("scan_error type=%s", type(e).__name__)
            return self._send(503, {"error": "dlp_scan_error"})  # 非 PASS

        resp = _result_to_response(result)
        resp.setdefault("latency_ms", {})["http_total"] = int((time.time() - t0) * 1000)
        return self._send(200, resp)

    def log_message(self, *args):  # 静音默认访问日志（避免把 path/query 记进日志）
        pass


def main():
    srv = ThreadingHTTPServer((BIND, PORT), Handler)
    srv.daemon_threads = True
    log.info(
        "dlp-http listening %s:%d inj=%s pool=%d l3_timeout=%.2fs langs=%s l3_unavail=%s",
        BIND, PORT, INJ.name, POOL_N, L3_TIMEOUT_S, ",".join(PRESIDIO_LANGS),
        L3_UNAVAILABLE_ACTION,
    )
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
