#!/usr/bin/env python3
#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
"""本地回归 — 用实例实测的 Presidio 原始输出做 mock 回放,验证 l3_presidio 弱 NER
过滤器三条修复语义(不依赖网络/实例,秒级跑完)。

三条断言(2026-07-30 实测数据):
  1. S6-01:en 整句 PERSON(含标点/CJK → _ner_plausible 丢)+ zh 华东区 LOCATION
     (合法但无强实体佐证 → 不转正)⇒ 最终 0 hits(修复前误 redact)。
  2. S2-14:运单号 CREDIT_CARD Luhn 全过、Presidio 给满分 1.0,流水语境钳到 0.4 ⇒ 丢
     (修复前 -0.4 剩 0.6 仍越阈误 redact)。
  3. L3-09 语义保留:PERSON(合法)+ EMAIL_ADDRESS(强实体)同现 ⇒ 弱实体转正,
     两者都命中(多实体组合 redact 不回归)。

跑法(repo 根目录): python3 testing/probes/test_l3_weak_ner_replay.py
"""
import sys
from pathlib import Path
from unittest import mock

_ENGINE = Path(__file__).resolve().parent.parent.parent / "engine"
sys.path.insert(0, str(_ENGINE))

from dlp import l3_presidio as l3  # noqa: E402

# —— 实例实测原始 NER 输出(2026-07-30, presidio-analyzer-zh) ——
REPLAY = {
    "S6-01": {"en": [
        {"entity_type": "PERSON", "score": 0.85, "start": 0, "end": 25},
        {"entity_type": "PERSON", "score": 0.85, "start": 29, "end": 37}],
        "zh": [
        {"entity_type": "DATE_TIME", "score": 0.85, "start": 2, "end": 6},
        {"entity_type": "LOCATION", "score": 0.85, "start": 9, "end": 12}]},
    "S2-14": {"en": [
        {"entity_type": "CREDIT_CARD", "score": 1.0, "start": 6, "end": 22}],
        "zh": []},
    "L3-09": {"en": [
        {"entity_type": "PERSON", "score": 0.85, "start": 0, "end": 5},
        {"entity_type": "EMAIL_ADDRESS", "score": 1.0, "start": 6, "end": 22}],
        "zh": []},
}
TEXTS = {
    "S6-01": "我们下个季度计划把华东区的获客成本压到行业均值的六成,渠道结构也要重排。",
    "S2-14": "物流运单号 4539123456783457,请查询签收状态。",
    "L3-09": "Li Na li.na@corp-mail.com 请回访",
}
EXPECT = {  # (期望 hit 的 entity 集合)
    "S6-01": set(),
    "S2-14": set(),
    "L3-09": {"PERSON", "EMAIL_ADDRESS"},
}


def fake_call(text, lang, timeout=2.0):
    for k, t in TEXTS.items():
        if t == text:
            return REPLAY[k][lang]
    return []


def main() -> int:
    failed = 0
    with mock.patch.object(l3, "_call_analyzer", fake_call):
        for k, t in TEXTS.items():
            hits, status = l3.scan(t)
            got = {h.entity for h in hits}
            ok = got == EXPECT[k] and status == "ok"
            print(f"{'✓' if ok else '✗'} {k}: status={status} "
                  f"entities={sorted(got) or '-'} 期望={sorted(EXPECT[k]) or '-'}")
            failed += 0 if ok else 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
