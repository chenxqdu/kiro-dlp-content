#!/usr/bin/env python3
#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
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

import concurrent.futures
import json
import logging
import os
import queue
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# 引擎包在镜像 /app 下（WORKDIR=/app, PYTHONPATH=/app 已内建），import dlp 已核实 OK。
from dlp import l4_semantic
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
# ---- L3.7 RAG 相似度检索(语义 EDM,默认关闭)----
# DLP_ENABLE_L37 开关;DLP_L37_URL 指向 VPC-local RAG 检索服务(g6 TEI/vLLM),回写进
# RAG_SERVICE_URL 供 l37_rag 读取(l37_rag 每次调用读 env,无 import 顺序坑)。
# ⚠ 红线:RAG embedding 后端必须 VPC-local;引擎侧只经 urllib 调独立服务。
ENABLE_L37 = os.environ.get("DLP_ENABLE_L37", "false").lower() in ("1", "true", "yes")
L37_THRESHOLD = float(os.environ.get("DLP_L37_THRESHOLD", "0.83"))
_L37_URL = os.environ.get("DLP_L37_URL", "").strip()
if _L37_URL:
    os.environ["RAG_SERVICE_URL"] = _L37_URL

log = logging.getLogger("dlp-http")
l4log = logging.getLogger("dlp-l4")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

# ---- L4 语义:三态开关 DLP_L4_MODE ∈ {off, async, sync} ----
# 引擎池恒纯 L0–L3.5(见 _CFG:l4_sync_block=False、_do_scan:run_async_l4=False);
# L4 一律在【server 层】用后台线程池直调 l4_semantic.analyze,不依赖 engine 内联。
#   off   —— 不跑 L4。
#   async —— (committed 默认)同步腿只 L0–L3.5、立即返回;后台异步跑 L4、命中落 sink,
#            【绝不改 verdict】。这是"L4 永不进入同步裁决"铁律的默认落点。
#   sync  —— 显式阻断态:请求线程带墙钟 deadline 等 L4;高置信(≥min_conf)→ server 就地
#            合成 BLOCK(top_layer=L4);超时→降级为异步告警 + 按 L0–L3.5 裁决放行(Q3-b)。
# 后端/模型/阈值与 mode 正交:
#   DLP_USE_BEDROCK_L4  L4 后端 Bedrock vs 离线启发式(⚠ Bedrock=内容出 VPC,见 compose 横幅)
#   DLP_L4_MODEL_KEY    main=Qwen3-32B / control=Llama-3.1-8B
#   DLP_L4_BLOCK_MIN_CONFIDENCE  sync 模式合成 BLOCK 的置信阈值
#   DLP_L4_TIMEOUT_MS   sync 墙钟上限 + 透传 boto read_timeout
#   DLP_L4_EXECUTOR_WORKERS / DLP_L4_QUEUE_MAX  后台线程池 + 背压上限(满则丢,不阻塞主链路)
#   DLP_L4_SINK_PATH    可选:告警 JSONL 追加写此文件(默认仅 stdout)
_BOOL = ("1", "true", "yes", "on")
_VALID_L4_MODES = ("off", "async", "sync")


def _resolve_l4_mode() -> str:
    """优先读 DLP_L4_MODE;未显式设置时从旧 flag 推导(带 deprecation warning)。"""
    raw = os.environ.get("DLP_L4_MODE")
    if raw is not None:
        m = raw.strip().lower()
        if m not in _VALID_L4_MODES:
            log.warning("DLP_L4_MODE=%r 非法,回退 off。合法值: %s", raw, _VALID_L4_MODES)
            return "off"
        return m
    # 向后兼容:旧 RUN_ASYNC_L4 / L4_SYNC_BLOCK 推导三态。
    old_run = os.environ.get("DLP_RUN_ASYNC_L4", "false").lower() in _BOOL
    old_block = os.environ.get("DLP_L4_SYNC_BLOCK", "false").lower() in _BOOL
    if not old_run:
        return "off"
    derived = "sync" if old_block else "async"
    log.warning(
        "DLP_RUN_ASYNC_L4/DLP_L4_SYNC_BLOCK 已弃用,请改用 DLP_L4_MODE。"
        "本次由旧 flag 推导为 DLP_L4_MODE=%s", derived,
    )
    return derived


L4_MODE = _resolve_l4_mode()
USE_BEDROCK_L4 = os.environ.get("DLP_USE_BEDROCK_L4", "false").lower() in _BOOL
L4_MODEL_KEY = os.environ.get("DLP_L4_MODEL_KEY", "main")  # main=Qwen3-32B / control=Llama-3.1-8B
L4_BLOCK_MIN_CONF = float(os.environ.get("DLP_L4_BLOCK_MIN_CONFIDENCE", "0.7"))
L4_TIMEOUT_S = float(os.environ.get("DLP_L4_TIMEOUT_MS", "4000")) / 1000.0
L4_EXEC_WORKERS = max(1, int(os.environ.get("DLP_L4_EXECUTOR_WORKERS", "2")))
L4_QUEUE_MAX = max(1, int(os.environ.get("DLP_L4_QUEUE_MAX", "32")))
L4_SINK_PATH = os.environ.get("DLP_L4_SINK_PATH", "").strip()
# 告警是否落 model rationale。true(默认,与方案一一致):落 rationale[:200]——⚠ Bedrock
# rationale 是模型自由文本,可能【回显输入片段】(实测真机 rationale 引用了待判公式),
# 这是知情接受的风险(不新增暴露面,原始 context/matched/span 恒不落)。
# false:更严档,彻底【不落 rationale】→ sink 保证零明文回显(生产偏好)。
L4_SINK_RATIONALE = os.environ.get("DLP_L4_SINK_RATIONALE", "true").lower() in _BOOL

# 后台执行器 + 背压信号量(main() 里初始化 executor;模块级先占位)。
_l4_executor: "concurrent.futures.ThreadPoolExecutor | None" = None
_l4_sem = threading.BoundedSemaphore(L4_QUEUE_MAX)

# ---------------- 引擎对象池（规格 D8：不用全局单锁串行化）----------------
# 用 N 个预构造引擎实例；每个请求独占一个，用完归还。无论 scan 是否线程安全都成立，
# 且并发上限 = POOL_N，形成天然背压（池空则新请求等待 POOL_WAIT，超时回 503 -> addon fail-closed）。
#
# EngineConfig：绝不传 presidio_url（真实签名无此参数）。
# ★ 池内 engine 恒【纯 L0–L3.5】:l4_sync_block=False 且 _do_scan 恒 run_async_l4=False,
#   engine 第 6 步内联 L4 在方案二【永不触发】。L4 全部改由 server 层后台线程池直调
#   l4_semantic.analyze(见 _l4_submit_async / _l4_sync_check),与方案一"L4 在主链路之外"
#   纪律一致,也堵死"engine 内联 + server 后台"双跑。use_bedrock/model_key 仅在 server
#   直调 analyze 时用,不进 EngineConfig。
_CFG = EngineConfig(
    presidio_languages=PRESIDIO_LANGS,
    l3_timeout=L3_TIMEOUT_S,
    l4_sync_block=False,
    run_l3_on_all_variants=RUN_L3_ON_ALL,
    l3_concurrency=L3_CONCURRENCY,
    enable_l37_rag=ENABLE_L37,          # 默认 False:L3.7 休眠,行为与历来一致
    l37_threshold=L37_THRESHOLD,
)
_pool: "queue.Queue[DLPEngine]" = queue.Queue()
for _ in range(max(1, POOL_N)):
    _pool.put(DLPEngine(_CFG))


def _do_scan(content):
    """从池取引擎跑 scan，用完归还。池空等待 POOL_WAIT，超时抛 queue.Empty -> 上层 503。"""
    eng = _pool.get(timeout=POOL_WAIT)
    try:
        # ★ 恒 run_async_l4=False:同步腿只跑 L0–L3.5,engine 内联 L4 永不触发。
        #   L4(off/async/sync 三态)全部由 server 层在 scan 之后编排(见 do_POST)。
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


# ---------------- L4 语义编排（server 层，主链路之外）----------------
# 引擎池已恒纯 L0–L3.5；L4 在此用后台线程池直调 l4_semantic.analyze。
#   async: fire-and-forget，命中落 sink，绝不改 verdict。
#   sync : 带墙钟 deadline 等结果，高置信合成 BLOCK；超时降级为异步告警 + 放行（Q3-b）。
# 背压 _l4_sem 单点 release（统一交 done-callback），防 "released too many times"。
def _l4_text_of(content) -> str:
    """取 L4 待判文本。与 engine.py 内联 L4 取文本逻辑一致（str 原样 / 否则 json.dumps）。"""
    return content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)


def _l4_sink(alert, mode: str) -> None:
    """落 L4 告警。★脱敏：只出 category/confidence/model[/rationale[:200]]，
    绝不落 context(=原文片段)/matched/span/原始 body（与 types.to_row 一致）。
    ★ rationale 由 DLP_L4_SINK_RATIONALE 门控:默认 true 落 rationale[:200](⚠ Bedrock
    自由文本可能回显输入片段,知情接受);false 则不落,sink 保证零明文回显。"""
    try:
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "kind": "l4_alert",
            "mode": mode,
            "category": getattr(alert, "category", None),
            "confidence": round(float(getattr(alert, "confidence", 0.0)), 4),
            "model": getattr(alert, "model", None),
        }
        if L4_SINK_RATIONALE:
            rec["rationale"] = (getattr(alert, "rationale", "") or "")[:200]
        line = json.dumps(rec, ensure_ascii=False)
    except Exception:
        return
    l4log.warning(line)  # stdout -> docker logs kiro-dlp-http 可捞
    if L4_SINK_PATH:
        try:
            with open(L4_SINK_PATH, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except Exception:
            pass  # 文件 sink 失败静默，绝不影响主链路
    # 文档化扩展点：EventBridge / SNS 可在此发布（留桩，不实现）。


def _l4_analyze(text: str):
    """后台线程里跑 analyze。异常内部吞掉回退 None，绝不冒泡影响主链路。"""
    try:
        alerts = l4_semantic.analyze(
            text,
            use_bedrock=USE_BEDROCK_L4,
            model_key=L4_MODEL_KEY,
            timeout_s=(L4_TIMEOUT_S if L4_MODE == "sync" else None),
        )
        return alerts[0] if alerts else None
    except Exception as e:
        l4log.warning("l4_analyze_error type=%s", type(e).__name__)
        return None


def _l4_done_callback(fut, mode: str) -> None:
    """统一收尾：release 背压信号量（单点） + 落 sink（若有告警）。"""
    try:
        alert = fut.result()
    except Exception:
        alert = None
    finally:
        try:
            _l4_sem.release()
        except ValueError:
            pass  # 防御：绝不 released too many times
    if alert is not None:
        _l4_sink(alert, mode)


def _l4_submit(text: str):
    """提交后台 L4。背压满 / executor 未就绪 -> 丢弃（不阻塞主链路），返回 future 或 None。"""
    if _l4_executor is None:
        return None
    if not _l4_sem.acquire(blocking=False):
        l4log.warning("l4_dropped reason=queue_full max=%d", L4_QUEUE_MAX)
        return None
    try:
        fut = _l4_executor.submit(_l4_analyze, text)
    except Exception:
        try:
            _l4_sem.release()  # 提交失败（如 executor 已关闭）：释放刚拿的信号量
        except ValueError:
            pass
        return None
    fut.add_done_callback(lambda f: _l4_done_callback(f, L4_MODE))
    return fut


def _l4_submit_async(text: str) -> None:
    """async 模式：fire-and-forget。sink + release 全交 done-callback。"""
    _l4_submit(text)


def _l4_sync_check(text: str):
    """sync 模式：带墙钟 deadline 等 L4。返回 AsyncAlert(命中) / None(未命中或超时降级放行)。
    超时【不 cancel】future，done-callback 仍后台补落 sink（Q3-b：超时降级为异步告警 + 放行）。"""
    fut = _l4_submit(text)
    if fut is None:
        return None  # 背压丢弃 / executor 未就绪 -> 视为未命中，放行
    try:
        return fut.result(timeout=L4_TIMEOUT_S)
    except concurrent.futures.TimeoutError:
        l4log.warning("l4_sync_timeout budget=%.2fs -> 降级异步告警+放行", L4_TIMEOUT_S)
        return None  # future 继续后台跑，done-callback 补落 sink
    except Exception:
        return None  # analyze 已内部吞异常；此处再兜底


def _apply_l4_block(resp: dict, alert) -> None:
    """sync 命中高置信 L4：就地把响应升级为 BLOCK。逐字镜像 engine.py 合成语义，
    但不依赖 engine 内联（D3）。调用方已确保 confidence ≥ L4_BLOCK_MIN_CONF。"""
    cat = getattr(alert, "category", "proprietary-source")
    conf = float(getattr(alert, "confidence", 0.0))
    resp["verdict"] = "BLOCK"
    resp["top_layer"] = "L4"
    resp.setdefault("rules", []).append({
        "layer": "L4",
        "rule": f"l4_semantic:{cat}",
        "entity": cat.upper().replace("-", "_"),
        "field_path": None,
        "confidence": conf,
        "action": "block",
    })
    resp.pop("redacted_body", None)  # BLOCK 短路，丢弃脱敏文本
    resp.setdefault("notes", []).append(
        f"L4 同步阻断(sync 模式):{cat} conf={conf:.2f}≥{L4_BLOCK_MIN_CONF} → BLOCK"
    )


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

        # ---- L4 语义编排（仅当同步腿放行/脱敏时介入；BLOCK/forced_block 不碰）----
        # fail-closed 契约：_result_to_response 已把 L3 不可达/REDACT 未生效短路成 BLOCK，
        # 故 L4 只在 PASS/REDACT 上跑 -> L4 超时降级绝不可能把 fail-closed 请求变放行(D6)。
        if L4_MODE != "off" and resp.get("verdict") in ("PASS", "REDACT"):
            l4_text = _l4_text_of(content)
            if L4_MODE == "async":
                _l4_submit_async(l4_text)          # fire-and-forget，绝不改 verdict
            elif L4_MODE == "sync":
                alert = _l4_sync_check(l4_text)     # 带墙钟；超时->None(降级放行)
                if alert is not None and float(getattr(alert, "confidence", 0.0)) >= L4_BLOCK_MIN_CONF:
                    _apply_l4_block(resp, alert)

        resp.setdefault("latency_ms", {})["http_total"] = int((time.time() - t0) * 1000)
        return self._send(200, resp)

    def log_message(self, *args):  # 静音默认访问日志（避免把 path/query 记进日志）
        pass


def _log_l4_banner():
    """启动横幅:打印 L4 三态状态;committed 默认 async+Bedrock=内容出 VPC,打刺眼横幅。"""
    if L4_MODE == "off":
        log.info("L4 mode=off: 同步腿只 L0–L3.5,不跑 L4,内容不出 VPC")
        return
    backend = "Bedrock(⚠出 VPC)" if USE_BEDROCK_L4 else "离线启发式(不出 VPC)"
    log.warning(
        "★ L4 mode=%s backend=%s model=%s min_conf=%.2f timeout=%.2fs workers=%d queue_max=%d sink=%s rationale=%s",
        L4_MODE, backend, L4_MODEL_KEY, L4_BLOCK_MIN_CONF, L4_TIMEOUT_S,
        L4_EXEC_WORKERS, L4_QUEUE_MAX, (L4_SINK_PATH or "stdout"),
        ("on(⚠可能回显片段)" if L4_SINK_RATIONALE else "off(零回显)"),
    )
    if USE_BEDROCK_L4:
        log.warning("=" * 72)
        log.warning("⚠  L4 后端 = Bedrock：待判内容将【出 VPC】发往 Bedrock。")
        log.warning("⚠  这是【演示/标定 shipped default】,刻意违反仓库红线(生产 L4 须 VPC-local)。")
        log.warning("⚠  生产部署【必须】置 DLP_USE_BEDROCK_L4=false 并切自托管 VPC-local(GPU+vLLM)。")
        log.warning("=" * 72)
    if L4_MODE == "sync":
        log.warning(
            "⚠  L4 mode=sync:高置信 L4 告警会【合成 BLOCK 升级 verdict】(top_layer=L4),"
            "刻意打破'L4 永不改 verdict';超时则降级为异步告警+放行(不阻断合法请求)。"
        )


def main():
    global _l4_executor
    srv = ThreadingHTTPServer((BIND, PORT), Handler)
    srv.daemon_threads = True
    log.info(
        "dlp-http listening %s:%d inj=%s pool=%d l3_timeout=%.2fs langs=%s l3_unavail=%s",
        BIND, PORT, INJ.name, POOL_N, L3_TIMEOUT_S, ",".join(PRESIDIO_LANGS),
        L3_UNAVAILABLE_ACTION,
    )
    # L4 后台执行器:仅在非 off 模式创建(daemon 线程,主链路之外)。
    if L4_MODE != "off":
        _l4_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=L4_EXEC_WORKERS, thread_name_prefix="l4",
        )
    _log_l4_banner()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        if _l4_executor is not None:
            _l4_executor.shutdown(wait=False, cancel_futures=True)


if __name__ == "__main__":
    main()
