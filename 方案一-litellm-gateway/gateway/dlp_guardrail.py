"""CorpDLPGuardrail —— LiteLLM 自定义 guardrail(方案一两个 hook,03 文档 §2/§6 阶段2)。

- mode=pre_call    → async_pre_call_hook:扫出站 prompt(messages 全量,含工具返回值回流
                     进下一轮上下文的 tool role 消息 —— 套件5 flowback 即走此口)。
- mode=pre_mcp_call → apply_guardrail:扫 MCP 工具调用参数文本。
                     (LiteLLM MCP 网关在 pre_mcp_call 时对 guardrail 调 apply_guardrail;
                      本类同时保留 scan_mcp_call() 供离线/直连构造 MCP dict 验证。)

裁决语义(与引擎 SPEC §2 一致):
- BLOCK  → 抛 HTTPException(400),请求不出网关;
- REDACT → 用 redacted 文本替换原文后放行;
- PASS   → 原样放行。
L4 永不进入同步裁决:同步扫描 run_async_l4=False;命中面(pass 的内容)投递异步 L4
队列(此处简化为 fire-and-forget task,生产应为持久队列)。

fail-closed 升级(规格 D4,与方案二 http_service/server.py 同语义):
引擎对「L3 不可达 / 部分语言失败 / 超时间预算截断」只写 notes、不改 verdict
(engine.py 的 _aggregate 只看 Hit.action,结构上不读 l3_state)——fail-closed
的责任在调用方。本网关据此扫 result.notes:
- 命中 L3 降级 marker → 默认强制升级为 BLOCK(400,forced_block=l3_unavailable),
  杜绝「Presidio 过载 → 本该 REDACT 的 PII 静默变 PASS」的 fail-open 通道
  (03 文档 §5「降级安全」判据;§9.4 曾坐实该缺口)。仅 DLP_L3_UNAVAILABLE_ACTION=keep
  退回旧行为(危险,仅供实验 D 对照);空串/拼写错误一律按 fail-closed 处理(默认拒绝)。
- 命中「REDACT 未生效」→ 恒强制 BLOCK(不受上述开关影响):脱敏落空 = 敏感
  内容仍在明文里,放行即泄漏。
- REDACT 生效但脱敏文本无法写回消息结构(多模态分段定位失败等)→ 亦 fail-closed
  拦截(forced_block=redact_writeback_failed),绝不放行未脱敏明文。

对外文案(_block_message):真实内容裁决优先于降级——内容本身命中 BLOCK 时给
永久性拒绝文案(按 L0/L1/L2 凭证密钥 · L3.5 内部专有信息分别措辞),不会改写成
「稍后重试」诱导对永远会被拦截的请求做无效重试;仅纯降级触发的强制 BLOCK 才提示重试。

红线:本文件不引入任何第三方云审查——L4 标定后端(Bedrock)只在异步告警路径,
且报告必须标注"仅功能验证,数据出 VPC,非生产配置"。
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any, List, Literal, Optional, Union

from fastapi import HTTPException

from litellm._logging import verbose_proxy_logger
from litellm.caching.caching import DualCache
from litellm.integrations.custom_guardrail import CustomGuardrail
from litellm.proxy._types import UserAPIKeyAuth

# 引擎以源码包挂载进容器(compose 挂 /app/dlp),纯 stdlib,无需安装
from dlp.engine import DLPEngine, EngineConfig
from dlp.types import InjectionPoint, Layer, Verdict

# L4 异步标定开关(阶段4 打开;经实例 IAM 角色调 Bedrock,不落长期凭证)
_USE_BEDROCK_L4 = os.getenv("DLP_L4_BEDROCK", "0") == "1"

# L3 降级动作:keep=保留引擎原判(危险,仅实验对照) | 其余一律 fail-closed(默认,安全)。
# 命名与语义对齐方案二 server.py 的同名 env。★默认拒绝语义:只有显式 "keep" 才退回旧
# 行为,空串/尾空格/拼写错误(如 "blok")都落到 fail-closed,绝不因配置手误静默 fail-open。
_L3_UNAVAILABLE_ACTION = os.getenv("DLP_L3_UNAVAILABLE_ACTION", "block").strip().lower()
_L3_FAIL_CLOSED = _L3_UNAVAILABLE_ACTION != "keep"
if _L3_UNAVAILABLE_ACTION not in ("block", "keep"):
    verbose_proxy_logger.warning(
        "DLP_L3_UNAVAILABLE_ACTION=%r 非法(仅 block|keep),按 fail-closed(block)处理",
        _L3_UNAVAILABLE_ACTION,
    )
# marker 集与方案二 server.py 逐字一致(engine.py 的 notes 措辞是两边共同契约)
_L3_UNAVAILABLE_MARKERS = ("analyzer 不可达", "部分语言失败", "L3 skipped")
_REDACT_INEFFECTIVE_MARKERS = ("REDACT 未生效",)

_engine = DLPEngine(EngineConfig(use_bedrock_l4=_USE_BEDROCK_L4))

# 简易指标累积(阶段3 压测读取;/tmp 卷可挂出)
_METRICS_PATH = os.getenv("DLP_METRICS_PATH", "/tmp/dlp_gateway_metrics.jsonl")


def _record(kind: str, verdict: str, latency_ms: dict, top_layer: str | None,
            forced_block: str = "") -> None:
    try:
        rec = {
            "ts": time.time(), "kind": kind, "verdict": verdict,
            "top_layer": top_layer, "latency_ms": latency_ms,
        }
        if forced_block:
            rec["forced_block"] = forced_block
        with open(_METRICS_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass  # 指标写失败不影响主链路


def _forced_block_reason(result) -> str:
    """规格 D4:notes 命中降级 marker 时给出强制 BLOCK 原因,否则空串。"""
    notes_txt = " ".join(result.notes or [])
    # REDACT 落空:命中片段不在原文字面,脱敏没生效 → 敏感内容仍在 → 恒 BLOCK
    if any(m in notes_txt for m in _REDACT_INEFFECTIVE_MARKERS):
        return "redaction_ineffective"
    # L3 不可达/超预算截断/部分语言失败:PII 可能漏检 → 默认 fail-closed(仅 keep 退回)
    if _L3_FAIL_CLOSED and any(m in notes_txt for m in _L3_UNAVAILABLE_MARKERS):
        return "l3_unavailable"
    return ""


async def _l4_async_alert(text: str) -> None:
    """L4 语义审查:异步告警路径,永不阻断(SPEC §5-L4)。"""
    try:
        from dlp import l4_semantic
        alerts = await asyncio.to_thread(
            l4_semantic.analyze, text, use_bedrock=_USE_BEDROCK_L4, model_key="main"
        )
        for a in alerts:
            verbose_proxy_logger.warning(
                "DLP L4 异步告警 category=%s conf=%.2f model=%s rationale=%s",
                a.category, a.confidence, a.model, a.rationale[:200],
            )
            _record("l4_alert", a.category, {}, "L4")
    except Exception as e:  # 告警链路故障只记录,绝不影响主链路
        verbose_proxy_logger.error("DLP L4 异步链路异常: %s", e)


def _extract_message_texts(messages: list) -> list[tuple[int, Optional[int], str]]:
    """取所有 role 的字符串 content(含 tool 消息 = flowback 回流面)。
    返回 (msg_index, seg_index, text):seg_index=None 表示整条 content 是字符串;
    seg_index=int 表示多模态分段列表里第 j 段的 text —— 供 REDACT 时按段精确写回
    (F1:此前 list content 只扫不写回,REDACT 静默降级为明文 PASS)。"""
    out: list[tuple[int, Optional[int], str]] = []
    for i, m in enumerate(messages or []):
        c = m.get("content")
        if isinstance(c, str) and c:
            out.append((i, None, c))
        elif isinstance(c, list):  # 多模态分段,只扫 text 段
            for j, seg in enumerate(c):
                if isinstance(seg, dict) and isinstance(seg.get("text"), str):
                    out.append((i, j, seg["text"]))
    return out


class CorpDLPGuardrail(CustomGuardrail):
    def __init__(self, **kwargs):
        self.optional_params = kwargs
        super().__init__(**kwargs)

    # ---- hook 1:出站 prompt(含 flowback 回流)----
    async def async_pre_call_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        cache: DualCache,
        data: dict,
        call_type: Any = None,
    ) -> Optional[Union[Exception, str, dict]]:
        messages = data.get("messages")
        if not messages:
            return data

        texts = _extract_message_texts(messages)
        # 会话滑窗:同请求内此前消息作为 window(EVA-03 跨消息拼接)
        t0 = time.perf_counter()
        window: list[str] = []
        mutated = False
        for idx, seg, text in texts:
            ip = (InjectionPoint.FLOWBACK
                  if messages[idx].get("role") == "tool" else InjectionPoint.PROMPT)
            # 扫描在线程池执行,避免阻塞事件循环(引擎是同步 CPU/HTTP 代码)
            result = await asyncio.to_thread(
                _engine.scan, text, injection_point=ip,
                run_async_l4=False, session_window=window or None,
            )
            self._dispose(result, kind="pre_call", hook="async_pre_call_hook")
            if result.verdict == Verdict.REDACT and result.redacted_text is not None:
                # 用脱敏文本按定位写回:字符串 content 整条替换;list content 精确回写
                # 命中的那一段 text(F1:漏了 seg 写回 → REDACT 级 PII 明文外发)。
                content = messages[idx].get("content")
                if seg is None and isinstance(content, str):
                    messages[idx]["content"] = result.redacted_text
                elif (seg is not None and isinstance(content, list)
                      and 0 <= seg < len(content)
                      and isinstance(content[seg], dict)):
                    content[seg]["text"] = result.redacted_text
                else:
                    # 无法按定位写回(结构异常)→ fail-closed:宁拦勿泄,不静默放行明文
                    self._raise_writeback_failed(result, hook="async_pre_call_hook")
                mutated = True
            window.append(text)

        # 同步放行面 → L4 异步语义审查(套件6:同步必 pass,仅异步告警)
        full_text = "\n".join(t for _, _, t in texts)
        asyncio.create_task(_l4_async_alert(full_text))

        verbose_proxy_logger.debug(
            "CorpDLP pre_call 完成 msgs=%d mutated=%s 总耗时=%.1fms",
            len(texts), mutated, (time.perf_counter() - t0) * 1000,
        )
        return data

    # ---- hook 2:统一 guardrail 通道(litellm main-latest,2026-07 实测)----
    # 类里一旦定义 apply_guardrail,pre_call / pre_mcp_call 都走 unified_guardrail:
    # 调用约定 apply_guardrail(inputs={texts:[...], tool_calls:[...], ...},
    # request_data=..., input_type="request", logging_obj=...),要求返回同形 dict
    # (texts 就地脱敏);BLOCK 用抛异常表达。旧的 text: str 契约仍兼容(MCP 直连)。
    async def apply_guardrail(
        self,
        inputs: Any = None,
        request_data: Optional[dict] = None,
        input_type: Optional[str] = None,
        logging_obj: Any = None,
        text: str = "",
        **kwargs: Any,
    ):
        # —— 新契约:inputs 为 GenericGuardrailAPIInputs(dict)——
        if isinstance(inputs, dict):
            texts: list = list(inputs.get("texts") or [])
            window: list[str] = []
            for i, t in enumerate(texts):
                if not isinstance(t, str) or not t:
                    continue
                result = await asyncio.to_thread(
                    _engine.scan, t, injection_point=InjectionPoint.PROMPT,
                    run_async_l4=False, session_window=window or None,
                )
                self._dispose(result, kind="pre_call", hook="apply_guardrail:texts")
                if result.verdict == Verdict.REDACT and result.redacted_text is not None:
                    texts[i] = result.redacted_text
                window.append(t)

            # tool_calls:function.arguments 是 JSON 串 → 按 MCP 注入点扫
            tool_calls = inputs.get("tool_calls")
            if isinstance(tool_calls, list):
                for tc in tool_calls:
                    fn = (tc or {}).get("function") or {}
                    args = fn.get("arguments")
                    if not isinstance(args, str) or not args:
                        continue
                    try:
                        call = {"tool": fn.get("name", "unknown"),
                                "arguments": json.loads(args)}
                    except (ValueError, TypeError):
                        call = {"tool": fn.get("name", "unknown"),
                                "arguments": {"_raw": args}}
                    result = await asyncio.to_thread(
                        _engine.scan, call, injection_point=InjectionPoint.MCP,
                        run_async_l4=False,
                    )
                    self._dispose(result, kind="pre_mcp_call", hook="apply_guardrail:tool_calls")
                    if result.verdict == Verdict.REDACT and result.redacted_text is not None:
                        try:  # redacted_text 是整个 call 的 JSON,取回 arguments 部分
                            fn["arguments"] = json.dumps(
                                json.loads(result.redacted_text).get("arguments", {}),
                                ensure_ascii=False)
                        except (ValueError, TypeError):
                            pass

            inputs["texts"] = texts
            # 同步放行面 → L4 异步语义审查(套件6)
            full = "\n".join(t for t in texts if isinstance(t, str))
            if full:
                asyncio.create_task(_l4_async_alert(full))
            return inputs

        # —— 旧契约:单段 text ——
        if not text and isinstance(inputs, str):
            text = inputs
        if not text:
            return inputs if inputs is not None else text
        result = await asyncio.to_thread(
            _engine.scan, text, injection_point=InjectionPoint.MCP, run_async_l4=False,
        )
        self._dispose(result, kind="pre_mcp_call", hook="apply_guardrail:text")
        asyncio.create_task(_l4_async_alert(text))
        if result.verdict == Verdict.REDACT and result.redacted_text is not None:
            return result.redacted_text
        return text

    @staticmethod
    def _block_message(result, forced: str) -> str:
        """按拦截来源给出准确文案(F4-b:BLOCK 不止凭证/密钥,专有代号/内部域名亦会触发)。
        真实内容裁决优先于降级原因(F2):内容里本就有不可外发信息时,不能改写成
        『稍后重试』——重试永远 BLOCK,只会误导 + 放大对已过载 Presidio 的重试风暴。"""
        # 1) 真实内容 BLOCK:永久性拒绝,按顶层来源措辞(即便同时命中 L3 降级 marker)
        if result.verdict == Verdict.BLOCK:
            top = result.top_layer
            if top in (Layer.L0, Layer.L1, Layer.L2):
                return "请求包含凭证/密钥级敏感信息,已被企业 DLP 网关拦截,请移除后再试。"
            if top == Layer.L35:
                return ("请求包含内部专有信息(项目代号/内部域名等),"
                        "已被企业 DLP 网关拦截,请移除后再试。")
            return "请求包含企业策略禁止外发的内容,已被企业 DLP 网关拦截。"
        # 2) 纯降级触发的强制 BLOCK:内容本身未判定敏感,属可恢复的服务端降级
        if forced == "l3_unavailable":
            return ("DLP 深度检测层(L3)暂不可用,按 fail-closed 策略暂拦此请求;"
                    "请稍后重试或联系管理员。")
        if forced == "redaction_ineffective":
            return "DLP 脱敏未能落到明文(命中片段无法定位),按 fail-closed 策略拦截。"
        return "请求已被企业 DLP 网关拦截。"

    @staticmethod
    def _dispose(result, kind: str, hook: str) -> None:
        """统一处置口:记指标 + BLOCK/强制升级抛 400。
        每次 scan 的结果都必须经此(单一路径,规格 D4 不允许有绕过 fail-closed 的分支)。
        """
        forced = _forced_block_reason(result)
        is_block = result.verdict == Verdict.BLOCK
        # F3/R3:verdict 统一小写 .value(pass/redact/block),不因 forced 写大写字面量;
        # forced 与否只由 forced_block 字段区分,既有小写消费方零改动。
        verdict = Verdict.BLOCK.value if (is_block or forced) else result.verdict.value
        _record(kind, verdict, result.latency_ms,
                result.top_layer.value if result.top_layer else None,
                forced_block=forced)
        if is_block or forced:
            rules = sorted({h.rule for h in result.hits})
            detail = {
                "error": "blocked_by_corp_dlp",
                "hook": hook,
                "top_layer": result.top_layer.value if result.top_layer else None,
                "rules": rules[:10],
                "message": CorpDLPGuardrail._block_message(result, forced),
            }
            # F2:真实内容 BLOCK 时,forced_block 只作次要标注,不改写永久性拒绝语义。
            if forced and not is_block:
                detail["forced_block"] = forced
            elif forced and is_block:
                detail["degraded"] = forced  # 内容已确定拦截,降级仅供诊断,非重试信号
            raise HTTPException(status_code=400, detail=detail)

    @staticmethod
    def _raise_writeback_failed(result, hook: str) -> None:
        """F1:REDACT 生效但无法把脱敏文本写回消息结构 → fail-closed 拦截,严禁放行明文。"""
        _record("pre_call", Verdict.BLOCK.value, result.latency_ms,
                result.top_layer.value if result.top_layer else None,
                forced_block="redact_writeback_failed")
        raise HTTPException(status_code=400, detail={
            "error": "blocked_by_corp_dlp",
            "hook": hook,
            "top_layer": result.top_layer.value if result.top_layer else None,
            "forced_block": "redact_writeback_failed",
            "message": "DLP 脱敏结果无法安全写回请求(消息结构异常),按 fail-closed 策略拦截。",
        })

    # ---- 直连口:构造好的 MCP dict(离线/阶段2 验证 field_path 定位用)----
    def scan_mcp_call(self, call: dict):
        """call = {"tool": ..., "arguments": {...}};返回 ScanResult(含 field_path 命中)。"""
        return _engine.scan(call, injection_point=InjectionPoint.MCP, run_async_l4=False)


corp_dlp_guardrail = CorpDLPGuardrail
