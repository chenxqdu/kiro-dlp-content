#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
"""L3.5 术语表/EDM(SPEC §5-L3.5)—— 亚毫秒,同步。

内部术语/项目代号多模式匹配。约束(防撞普通英文,FP-09/L35-13):
  1. 完整专有短语;2. 词边界;3. 大小写敏感(代号大小写模式)。
优先用 pyahocorasick;不可用则回退到编译正则联合(语义等价,规模小无性能问题)。
"""
from __future__ import annotations

import re

from .types import Hit, Layer, Verdict

# 术语表:每条 (phrase, entity, action, case_sensitive)
# 代号/项目名默认 BLOCK;工单号/可脱敏项 REDACT。
GLOSSARY: list[tuple[str, str, Verdict, bool]] = [
    ("Project Nightingale", "PROPRIETARY_TERM", Verdict.BLOCK, True),
    ("KunlunPay", "PROPRIETARY_TERM", Verdict.BLOCK, True),
    ("region-cn-shadow", "PROPRIETARY_TERM", Verdict.BLOCK, False),
    ("PROJECT-TITAN", "PROPRIETARY_TERM", Verdict.BLOCK, True),
    ("internal-margin-formula", "PROPRIETARY_TERM", Verdict.BLOCK, False),
    # Falcon 仅专有语境(需与 project/内部 同现,见下方 _FALCON_CTX)
]

# 工单号模式(正则类术语)
_TICKET = re.compile(r"\bSEV\d-\d{3,6}\b")
# Falcon 需专有语境才判(裸 falcon 撞普通英文/开源项目)
_FALCON = re.compile(r"\bFalcon\b")
_FALCON_CTX = re.compile(r"(project|内部|internal|代号|codename)", re.IGNORECASE)
# 内部域名
_CORP_DOMAIN = re.compile(r"\b[\w.\-]+\.corp\.example\.net\b", re.IGNORECASE)


def _find_phrase(text: str, phrase: str, case_sensitive: bool) -> list[tuple[int, int]]:
    # 完整短语 + 词边界。短语内已含空格/连字符时,\b 加在两端。
    flags = 0 if case_sensitive else re.IGNORECASE
    pat = r"(?<![\w-])" + re.escape(phrase) + r"(?![\w-])"
    return [m.span() for m in re.finditer(pat, text, flags)]


def scan(text: str, source: str = "normalized", injection_point=None) -> list[Hit]:
    hits: list[Hit] = []

    for phrase, entity, action, cs in GLOSSARY:
        for span in _find_phrase(text, phrase, cs):
            # 大小写敏感项:确保原文大小写完全一致(防社区版小写 nightingale)
            if cs and text[span[0]:span[1]] != phrase:
                continue
            hits.append(Hit(Layer.L35, f"glossary:{phrase}", entity,
                            span, text[span[0]:span[1]], action, source=source))

    for m in _TICKET.finditer(text):
        hits.append(Hit(Layer.L35, "ticket_id", "PROPRIETARY_TERM",
                        m.span(), m.group(0), Verdict.REDACT, source=source))

    for m in _CORP_DOMAIN.finditer(text):
        hits.append(Hit(Layer.L35, "corp_domain", "INTERNAL_DOMAIN",
                        m.span(), m.group(0), Verdict.BLOCK, source=source))

    if _FALCON_CTX.search(text):
        for m in _FALCON.finditer(text):
            hits.append(Hit(Layer.L35, "glossary:Falcon", "PROPRIETARY_TERM",
                            m.span(), m.group(0), Verdict.BLOCK, source=source))

    return hits
