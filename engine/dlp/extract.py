#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
"""MCP / 嵌套 JSON 展开(SPEC §6)。

把 content 抽成若干【文本单元 (text, field_path)】:
- str  → 单个单元, field_path=None
- dict → MCP 调用 {"tool","arguments":{...}}:递归展开所有字符串叶子,
         每个叶子带点号+下标路径 field_path。tool 名也扫(field_path="tool")。
数字/布尔/None 叶子跳过(不是待扫文本)。
"""
from __future__ import annotations

# 同义工具名归一(MCP-01):写文件类工具视作同一处理
_WRITE_SYNONYMS = {"write_file", "create_file", "edit_file", "put_file", "save_file"}

# 抽取时跳过的子树键:纯客户端注入的工具【定义】schema(name/description/inputSchema),
# 非用户/模型生成内容。真机实测:Kiro 每次注入 100+ 工具目录,其 description 被
# stripped-sep 变体(删空格→高熵串)+ 无边界语境词(auth/token/credential 子串)大量
# 误报 L2 high_entropy_secret=BLOCK,且撑大 body 拖慢 L3。故抽取阶段整棵跳过。
# 只跳工具【定义】;工具【调用参数/结果】不在此键下,仍全量扫。DLP 为旁路检查器,
# 跳过只改"扫什么算 verdict",不改转发给上游的 body。
_SKIP_SUBTREE_KEYS = frozenset({
    "toolSpecification",              # 工具定义 schema(客户端注入 boilerplate)
    # 协议元数据字段:非用户内容,却被 presidio 误判(profileArn 整串判 PERSON、
    # agentTaskType/reasoning.effort 短枚举值误命中),把一切请求拖成 REDACT;
    # 更糟的是 REDACT 会改写这些协议字段,直接破坏请求合法性。一律不扫。
    "profileArn", "agentTaskType", "additionalModelRequestFields",
    # 真机事故补齐(2026-08-03):agentMode="vibe" 被 presidio 判 LOCATION → REDACT
    # 改写 → Kiro 400 Improperly formed request。连同 CodeWhisperer 协议里其余
    # 枚举/ID 字段一并跳过——它们永远不是用户内容,却都可能被 NER 误判。
    "agentMode", "conversationId", "chatTriggerType", "customizationArn", "origin",
    # 真机第三轮发现:agentContinuationId(UUID)被 L0 数字段规则误命中并被 REDACT 改写,
    # 本次 Kiro 容忍了,但协议 ID 字段被改写随时可能 400,一并跳过。
    "agentContinuationId",
})


def canonical_tool(name: str | None) -> str | None:
    if not name:
        return None
    return "write_file" if name in _WRITE_SYNONYMS else name


def _walk(obj, prefix: str, out: list[tuple[str, str | None]]) -> None:
    if isinstance(obj, str):
        out.append((obj, prefix or None))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if k in _SKIP_SUBTREE_KEYS:
                continue  # 跳过工具定义 schema(客户端 boilerplate,非内容)
            p = f"{prefix}.{k}" if prefix else str(k)
            if p.endswith("conversationState.history"):
                # 增量扫描:跳过会话历史。每条消息在它作为 currentMessage 发送的那一轮
                # 已被全量扫描裁决(BLOCK 的根本进不了历史);每轮重扫历史既冗余,又把
                # 历史里的 presidio 人名/地名命中拖成全请求 REDACT、L2 误报拖成 BLOCK。
                continue
            _walk(v, p, out)
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _walk(v, f"{prefix}[{i}]", out)
    # int/float/bool/None → 跳过


def extract_units(content, injection_point=None) -> list[tuple[str, str | None]]:
    """返回 [(text, field_path), ...]。"""
    if isinstance(content, str):
        return [(content, None)]

    out: list[tuple[str, str | None]] = []
    if isinstance(content, dict):
        tool = content.get("tool")
        if isinstance(tool, str):
            out.append((tool, "tool"))
        args = content.get("arguments", content.get("args", {}))
        _walk(args, "", out)
        # 有些 MCP 形态把参数直接摊在顶层(无 arguments 包裹)
        if not args and not tool:
            _walk(content, "", out)
    else:
        _walk(content, "", out)
    return out
