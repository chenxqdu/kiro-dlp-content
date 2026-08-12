#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
"""L2 高熵 + 语境(SPEC §5-L2)—— ~10ms,同步。

高熵串**且**有赋值/密钥语境词 → BLOCK。
无语境高熵一律 PASS:UUID / data:image / git SHA / build_id / lockfile integrity。
"""
from __future__ import annotations

import math
import re

from .types import Hit, Layer, Verdict

# 候选高熵 token(长度 >=20 的 base64ish / hexish)
_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")

# 结构豁免(FP-01/FP-03/FP-04):这些"看着高熵"但有确定结构 → PASS
_UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                   r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_GIT_SHA = re.compile(r"\b[0-9a-f]{40}\b|\b[0-9a-f]{7,12}\b")
_DATA_URI = re.compile(r"data:[\w.+\-]+/[\w.+\-]+;base64,")
_LOCKFILE_INTEGRITY = re.compile(r"sha(?:256|512)-|integrity[\"']?\s*[:=]")

# 密钥/赋值语境词(必须出现在 token 附近才判)
_CTX = re.compile(
    # 词边界加固:真机误报根因之一——无边界时 auth 匹配 authorization/authenticated、
    # credential 匹配 credentials 等散文词,英文工具描述/历史消息大面积假阳。
    # 显式收录 authorization/credentials(真语境词),排除 authenticated/authorize 等动词形态。
    r"\b(password|passwd|pwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|"
    r"private[_\-]?key|credentials?|authorization|auth|bearer)\b",
    re.IGNORECASE,
)


def shannon(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _structurally_exempt(text: str, span: tuple[int, int]) -> bool:
    tok = text[span[0]:span[1]]
    # data:image 前缀
    lo = max(0, span[0] - 32)
    prefix = text[lo:span[0]]
    if _DATA_URI.search(prefix + tok[:16]):
        return True
    if _LOCKFILE_INTEGRITY.search(prefix):
        return True
    # token 自身是 UUID / git SHA 形态
    if _UUID.fullmatch(tok):
        return True
    if re.fullmatch(r"[0-9a-f]{40}", tok) or re.fullmatch(r"[0-9a-f]{7,12}", tok):
        return True
    return False


def scan(text: str, source: str = "normalized") -> list[Hit]:
    hits: list[Hit] = []
    # 先摘掉明显结构串所在区间,避免它们进入语境判定
    for m in _TOKEN.finditer(text):
        tok = m.group(0)
        if len(tok) < 20:
            continue
        if _structurally_exempt(text, m.span()):
            continue
        ent = shannon(tok)
        if ent < 4.0:
            continue  # 熵不够 → 不是随机密钥
        # 语境:token 前后 32 字符窗口内需有密钥语境词
        lo = max(0, m.start() - 40)
        hi = min(len(text), m.end() + 8)
        window = text[lo:hi]
        if not _CTX.search(window):
            continue  # 无语境高熵 → PASS(FP-01/03/04)
        hits.append(Hit(Layer.L2, "high_entropy_secret", "GENERIC_SECRET",
                        m.span(), tok, Verdict.BLOCK, confidence=min(1.0, ent / 6.0),
                        source=source))
    return hits
