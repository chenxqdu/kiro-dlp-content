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
from dlp.types import InjectionPoint, Verdict

# L4 异步标定开关(阶段4 打开;经实例 IAM 角色调 Bedrock,不落长期凭证)
_USE_BEDROCK_L4 = os.getenv("DLP_L4_BEDROCK", "0") == "1"

_engine = DLPEngine(EngineConfig(use_bedrock_l4=_USE_BEDROCK_L4))

# 简易指标累积(阶段3 压测读取;/tmp 卷可挂出)
_METRICS_PATH = os.getenv("DLP_METRICS_PATH", "/tmp/dlp_gateway_metrics.jsonl")


def _record(kind: str, verdict: str, latency_ms: dict, top_layer: str | None) -> None:
    try:
        with open(_METRICS_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "ts": time.time(), "kind": kind, "verdict": verdict,
                "top_layer": top_layer, "latency_ms": latency_ms,
            }, ensure_ascii=False) + "\n")
    except OSError:
        pass  # 指标写失败不影响主链路


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


def _extract_message_texts(messages: list) -> list[tuple[int, str]]:
    """取所有 role 的字符串 content(含 tool 消息 = flowback 回流面)。"""
    out = []
    for i, m in enumerate(messages or []):
        c = m.get("content")
        if isinstance(c, str) and c:
            out.append((i, c))
        elif isinstance(c, list):  # 多模态分段,只扫 text 段
            for j, seg in enumerate(c):
                if isinstance(seg, dict) and isinstance(seg.get("text"), str):
                    out.append((i, seg["text"]))
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
        for idx, text in texts:
            ip = (InjectionPoint.FLOWBACK
                  if messages[idx].get("role") == "tool" else InjectionPoint.PROMPT)
            # 扫描在线程池执行,避免阻塞事件循环(引擎是同步 CPU/HTTP 代码)
            result = await asyncio.to_thread(
                _engine.scan, text, injection_point=ip,
                run_async_l4=False, session_window=window or None,
            )
            _record("pre_call", result.verdict.value, result.latency_ms,
                    result.top_layer.value if result.top_layer else None)

            if result.verdict == Verdict.BLOCK:
                rules = sorted({h.rule for h in result.hits})
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "blocked_by_corp_dlp",
                        "hook": "async_pre_call_hook",
                        "top_layer": result.top_layer.value if result.top_layer else None,
                        "rules": rules[:10],
                        "message": "请求包含不可外发的敏感内容(凭证/密钥级),已被企业 DLP 网关拦截。",
                    },
                )
            if result.verdict == Verdict.REDACT and result.redacted_text is not None:
                # 用脱敏文本替换该消息(list content 场景整体替换为脱敏串)
                if isinstance(messages[idx].get("content"), str):
                    messages[idx]["content"] = result.redacted_text
                mutated = True
            window.append(text)

        # 同步放行面 → L4 异步语义审查(套件6:同步必 pass,仅异步告警)
        full_text = "\n".join(t for _, t in texts)
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
                _record("pre_call", result.verdict.value, result.latency_ms,
                        result.top_layer.value if result.top_layer else None)
                self._raise_if_block(result, hook="apply_guardrail:texts")
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
                    _record("pre_mcp_call", result.verdict.value, result.latency_ms,
                            result.top_layer.value if result.top_layer else None)
                    self._raise_if_block(result, hook="apply_guardrail:tool_calls")
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
        _record("pre_mcp_call", result.verdict.value, result.latency_ms,
                result.top_layer.value if result.top_layer else None)
        self._raise_if_block(result, hook="apply_guardrail:text")
        asyncio.create_task(_l4_async_alert(text))
        if result.verdict == Verdict.REDACT and result.redacted_text is not None:
            return result.redacted_text
        return text

    @staticmethod
    def _raise_if_block(result, hook: str) -> None:
        if result.verdict == Verdict.BLOCK:
            rules = sorted({h.rule for h in result.hits})
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "blocked_by_corp_dlp",
                    "hook": hook,
                    "top_layer": result.top_layer.value if result.top_layer else None,
                    "rules": rules[:10],
                    "message": "请求包含不可外发的敏感内容(凭证/密钥级),已被企业 DLP 网关拦截。",
                },
            )

    # ---- 直连口:构造好的 MCP dict(离线/阶段2 验证 field_path 定位用)----
    def scan_mcp_call(self, call: dict):
        """call = {"tool": ..., "arguments": {...}};返回 ScanResult(含 field_path 命中)。"""
        return _engine.scan(call, injection_point=InjectionPoint.MCP, run_async_l4=False)


corp_dlp_guardrail = CorpDLPGuardrail
