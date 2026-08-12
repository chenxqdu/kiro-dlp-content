#!/usr/bin/env python3
#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
"""分层完备单测 harness —— 直接调每层 scan(),不经引擎聚合(与 run_offline.py 的
场景矩阵互补:那边验"整机裁决",这边验"每层每条规则的正例/豁免/边界")。

向量文件:tests/fixtures_layers/{l0,l1,l2,l3,l35,egress,norm,l4}.json
向量 schema(按 layer 取所需字段):
  {
    "id": "L0-POS-01",
    "layer": "L0" | "L1" | "L2" | "L3" | "L3.5" | "EGRESS" | "NORM" | "L4",
    "note": "这条测什么(规则名/FP 编号)",
    "requires": null | "presidio" | "bedrock",   # 环境依赖,缺则 SKIP
    # —— L0/L1/L2/L3/L3.5:文本入参 ——
    "text": "...",
    "must_hit":     [{"rule": "...", "entity": "...", "action": "block|redact"}],  # 子集匹配
    "must_not_hit": [{"rule": "..."} | {"entity": "..."}],
    "exact_none": true,          # 可选:断言零命中(比 must_not_hit 更强)
    # —— EGRESS:工具调用入参 ——
    "tool": "execute_shell", "args": {"command": "..."},
    # —— NORM:预处理变体断言 ——
    "func": "expand" | "normalize" | "strip_separators" | "fold_concat",
    "session_window": ["..."],               # 仅 expand
    "expect_contains":     ["子串", ...],     # 任一变体含该子串即过(expand 对变体列表;其余对返回串)
    "expect_not_contains": ["子串", ...],
    # —— L4:告警断言 ——
    "use_bedrock": false,
    "expect_alert": "proprietary-business-logic" | null,   # null=必须无告警
  }

跑法:
  python3 -m tests.run_layers [--layer L0] [--no-color] [--bedrock]
本地(无 Presidio):L3 向量自动 SKIP;--bedrock 才跑 requires=bedrock 的 L4 向量
(⚠ Bedrock=数据出 VPC,仅功能验证非生产)。
退出码:任何 fail → 1(SKIP 不算 fail)。
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

_ENGINE_ROOT = Path(__file__).resolve().parent.parent
if str(_ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_ENGINE_ROOT))

from dlp import (  # noqa: E402
    egress,
    l0_regex,
    l1_secrets,
    l2_entropy,
    l35_glossary,
    l37_rag,
    l3_presidio,
    l4_semantic,
    normalize,
)

FIXTURE_DIR = _ENGINE_ROOT / "tests" / "fixtures_layers"
LAYER_FILES = {"L0": "l0.json", "L1": "l1.json", "L2": "l2.json", "L3": "l3.json",
               "L3.5": "l35.json", "L3.7": "l37.json", "EGRESS": "egress.json",
               "NORM": "norm.json", "L4": "l4.json"}

_C = {"ok": "\033[32m", "bad": "\033[31m", "skip": "\033[33m", "z": "\033[0m"}


def _paint(s: str, key: str, color: bool) -> str:
    return f"{_C[key]}{s}{_C['z']}" if color else s


def _presidio_up() -> bool:
    """探测 analyzer 是否可达(与 l3_presidio 同一 URL)。"""
    url = l3_presidio.ANALYZER_URL.replace("/analyze", "/health")
    try:
        with urllib.request.urlopen(url, timeout=3):
            return True
    except (urllib.error.URLError, OSError, ValueError):
        return False


def _rag_up() -> bool:
    """探测 VPC-local RAG 检索服务是否可达(与 l37_rag 同源 URL 的 /health)。"""
    url = l37_rag.RAG_SERVICE_URL.rsplit("/", 1)[0] + "/health"
    try:
        with urllib.request.urlopen(url, timeout=3):
            return True
    except (urllib.error.URLError, OSError, ValueError):
        return False


def _hit_matches(hits, want: dict) -> bool:
    for h in hits:
        if "rule" in want and h.rule != want["rule"]:
            continue
        if "entity" in want and h.entity != want["entity"]:
            continue
        if "action" in want and h.action.value != want["action"]:
            continue
        return True
    return False


def _check_hits(hits, vec: dict) -> list[str]:
    reasons = []
    if vec.get("exact_none") and hits:
        reasons.append(f"期望零命中,实际 {[(h.rule, h.action.value) for h in hits]}")
    for want in vec.get("must_hit", []):
        if not _hit_matches(hits, want):
            reasons.append(f"缺 must_hit {want}")
    for nono in vec.get("must_not_hit", []):
        if _hit_matches(hits, nono):
            reasons.append(f"命中了 must_not_hit {nono}")
    return reasons


def run_vector(vec: dict, bedrock: bool, presidio: bool, rag: bool = False) -> tuple[str, list[str], float]:
    """返回 (status, reasons, latency_ms)。status ∈ {pass, fail, skip}。"""
    layer = vec["layer"]
    req = vec.get("requires")
    if req == "presidio" and not presidio:
        return "skip", ["需 Presidio(实例上跑)"], 0.0
    if req == "bedrock" and not bedrock:
        return "skip", ["需 --bedrock(数据出 VPC,仅功能验证)"], 0.0
    if req == "rag" and not rag:
        return "skip", ["需 RAG embedding 服务(VPC-local,g6 TEI/vLLM)"], 0.0

    t0 = time.perf_counter()
    if layer in ("L0", "L1", "L2", "L3.5"):
        fn = {"L0": l0_regex.scan, "L1": l1_secrets.scan,
              "L2": l2_entropy.scan, "L3.5": l35_glossary.scan}[layer]
        hits = fn(vec["text"])
        reasons = _check_hits(hits, vec)

    elif layer == "L3":
        hits, status = l3_presidio.scan(vec["text"])
        if status == "unreachable":
            return "skip", ["analyzer unreachable"], 0.0
        reasons = _check_hits(hits, vec)
        if status == "partial":
            reasons.append("L3 partial(部分语言失败)——结果不完整,判 fail 以免假绿")

    elif layer == "L3.7":
        hits, status = l37_rag.scan(vec["text"])
        if status == "unreachable":
            return "skip", ["RAG 服务 unreachable"], 0.0
        reasons = _check_hits(hits, vec)

    elif layer == "EGRESS":
        hits = egress.scan_channel(vec.get("tool"), vec.get("args", {}))
        reasons = _check_hits(hits, vec)

    elif layer == "NORM":
        func = vec.get("func", "expand")
        if func == "expand":
            out = normalize.expand(vec["text"], session_window=vec.get("session_window"))
            blob_list = out
        else:
            r = getattr(normalize, func)(vec["text"])
            blob_list = [r if isinstance(r, str) else ""]
        reasons = []
        for sub in vec.get("expect_contains", []):
            if not any(sub in (b or "") for b in blob_list):
                reasons.append(f"无任何变体含 {sub!r}")
        for sub in vec.get("expect_not_contains", []):
            if any(sub in (b or "") for b in blob_list):
                reasons.append(f"存在变体含 {sub!r}(不应出现)")

    elif layer == "L4":
        use_bedrock = bool(vec.get("use_bedrock"))
        alerts = l4_semantic.analyze(vec["text"], use_bedrock=use_bedrock)
        got = alerts[0].category if alerts else None
        want = vec.get("expect_alert")
        reasons = [] if got == want else [f"告警期望 {want} 实际 {got}"]
        if use_bedrock and alerts and not alerts[0].model.startswith("bedrock:"):
            reasons.append(f"要求 bedrock 后端,实际 {alerts[0].model}(静默回退启发式)")

    else:
        reasons = [f"未知 layer {layer}"]

    ms = (time.perf_counter() - t0) * 1000
    return ("pass" if not reasons else "fail"), reasons, ms


def main() -> int:
    ap = argparse.ArgumentParser(description="分层完备单测 harness")
    ap.add_argument("--layer", default=None, help="只跑某层(L0/L1/L2/L3/L3.5/EGRESS/NORM/L4)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--bedrock", action="store_true",
                    help="跑 requires=bedrock 向量(⚠ 数据出 VPC,仅功能验证)")
    args = ap.parse_args()
    color = not args.no_color

    presidio = _presidio_up()
    rag = _rag_up()
    layers = [args.layer] if args.layer else list(LAYER_FILES)

    rows, summary = [], {}
    missing = []
    for layer in layers:
        fp = FIXTURE_DIR / LAYER_FILES[layer]
        if not fp.exists():
            missing.append(fp.name)
            continue
        vectors = json.loads(fp.read_text(encoding="utf-8"))
        agg = summary.setdefault(layer, {"pass": 0, "fail": 0, "skip": 0, "total": 0})
        for vec in vectors:
            status, reasons, ms = run_vector(vec, args.bedrock, presidio, rag)
            agg["total"] += 1
            agg[status] += 1
            rows.append((vec["id"], layer, status, reasons, ms, vec.get("note", "")))

    print("=" * 108)
    print(f"{'ID':<14}{'层':<8}{'✓':<3}{'ms':>8}  说明")
    print("-" * 108)
    for vid, layer, status, reasons, ms, note in rows:
        mark = {"pass": "✓", "fail": "✗", "skip": "~"}[status]
        key = {"pass": "ok", "fail": "bad", "skip": "skip"}[status]
        print(f"{vid:<14}{layer:<8}{_paint(mark, key, color):<3}{ms:>8.2f}  {note[:70]}")
        for r in reasons if status == "fail" else []:
            print(f"              {_paint('· ' + r, 'bad', color)}")
        if status == "skip":
            print(f"              {_paint('· ' + reasons[0], 'skip', color)}")

    print("=" * 108)
    grand = {"pass": 0, "fail": 0, "skip": 0, "total": 0}
    for layer in layers:
        if layer not in summary:
            continue
        a = summary[layer]
        for k in grand:
            grand[k] += a[k]
        print(f"  {layer:<8}: {a['pass']}/{a['total']} 通过  fail={a['fail']} skip={a['skip']}")
    print("-" * 108)
    print(f"  合计: {grand['pass']}/{grand['total']}  fail={grand['fail']} skip={grand['skip']}"
          f"  (presidio={'可达' if presidio else '缺席→L3 skip'},"
          f" bedrock={'开' if args.bedrock else '关'},"
          f" rag={'可达' if rag else '缺席→L3.7 skip'})")
    if missing:
        print(_paint(f"⚠ 缺向量文件: {', '.join(missing)}", "skip", color))
    return 1 if (grand["fail"] > 0 or missing) else 0


if __name__ == "__main__":
    sys.exit(main())
