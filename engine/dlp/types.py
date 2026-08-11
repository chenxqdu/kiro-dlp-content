"""DLP 分层引擎 —— 顶层数据结构(SPEC §1)。

同步链路只放 L0–L3.5;引擎 scan() 里 L4 仅产 AsyncAlert,永不写入 verdict。
(部署层例外:方案二 :9000 的 DLP_L4_MODE=sync 可在【引擎之外】就地把高置信 L4
 告警合成 BLOCK;引擎本身不变。见 SPEC §L4。)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Verdict(str, Enum):
    PASS = "pass"        # 放行
    REDACT = "redact"    # 脱敏后放行
    BLOCK = "block"      # 拦截


class Layer(str, Enum):
    L0 = "L0"            # 正则/词表
    L1 = "L1"            # detect-secrets/gitleaks 类签名
    L2 = "L2"            # 高熵 + 语境
    L3 = "L3"            # Presidio PII/NER
    L35 = "L3.5"         # 术语表/EDM (Aho-Corasick)
    L4 = "L4"            # 语义 LLM —— 仅异步


# 层序:用于 top_layer "最低有效层" 计算(值越小越靠前)。
_LAYER_ORDER = {
    Layer.L0: 0,
    Layer.L1: 1,
    Layer.L2: 2,
    Layer.L3: 3,
    Layer.L35: 4,
    Layer.L4: 5,
}


def layer_rank(layer: Layer) -> int:
    return _LAYER_ORDER[layer]


class InjectionPoint(str, Enum):
    PROMPT = "prompt"        # 用户消息 / 代码上下文
    MCP = "mcp"              # MCP 工具调用参数
    FLOWBACK = "flowback"    # 工具返回值回流进下一轮上下文
    EGRESS = "egress"        # 通道级(shell/git/http-body/db)


@dataclass
class Hit:
    layer: Layer                     # 命中层
    rule: str                        # 规则标识,如 "aws_access_key"
    entity: str                      # 实体类型,如 "AWS_ACCESS_KEY" / "PERSON"
    span: tuple[int, int]            # 在【归一化后文本】中的 [start,end);无精确 span 用 (-1,-1)
    matched: str                     # 命中的原文片段(报告展示时自行截断)
    action: Verdict                  # 该 hit 期望动作:BLOCK 或 REDACT(单 hit 不为 PASS)
    confidence: float = 1.0          # [0,1];L3 用 Presidio score,确定性层固定 1.0
    source: str = "normalized"       # "raw" / "normalized" / "decoded:base64" 等,标注命中来自哪条预处理路径
    field_path: str | None = None    # MCP/嵌套 JSON 命中的字段路径,如 "headers.Authorization"

    def dedup_key(self) -> tuple:
        return (self.rule, self.span, self.field_path, self.entity)


@dataclass
class AsyncAlert:
    layer: Layer                     # 恒为 Layer.L4
    category: str                    # "proprietary-source" / "proprietary-business-logic"
    confidence: float
    rationale: str                   # LLM 给的简短理由(供追溯)
    context: str                     # 触发告警的上下文片段(截断)
    model: str                       # "bedrock:qwen3-32b" 等 —— 标定用,非生产


@dataclass
class ScanResult:
    verdict: Verdict                                        # 同步裁决:仅由 L0–L3.5 hits 聚合
    hits: list[Hit] = field(default_factory=list)           # 所有同步命中(可跨层多条)
    top_layer: Layer | None = None                          # 触发最终 verdict 的"最低有效层"
    redacted_text: str | None = None                        # verdict==REDACT 时给出;BLOCK/PASS 为 None
    async_alerts: list[AsyncAlert] = field(default_factory=list)   # L4 告警(同步返回时通常为空)
    latency_ms: dict[str, float] = field(default_factory=dict)     # 每层耗时 + total
    normalized_variants: list[str] = field(default_factory=list)   # 预处理产出的所有回扫变体
    notes: list[str] = field(default_factory=list)          # 已知逃逸缺口标注

    def to_row(self) -> dict:
        """离线 harness 用的扁平化视图。"""
        return {
            "verdict": self.verdict.value,
            "top_layer": self.top_layer.value if self.top_layer else None,
            "hits": [
                {
                    "layer": h.layer.value,
                    "rule": h.rule,
                    "entity": h.entity,
                    "action": h.action.value,
                    "source": h.source,
                    "field_path": h.field_path,
                    "matched": h.matched[:64],
                }
                for h in self.hits
            ],
            "async_alerts": [
                {"category": a.category, "confidence": a.confidence, "model": a.model}
                for a in self.async_alerts
            ],
            "latency_ms": self.latency_ms,
            "notes": self.notes,
        }
