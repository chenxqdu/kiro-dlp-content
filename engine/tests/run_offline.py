#!/usr/bin/env python3
#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
"""离线单测 harness(SPEC §8)。

- 载入 6 套件 fixtures,逐条 engine.scan(content, injection_point=..., session_window=...)。
  套件6 传 run_async_l4=True。
- 判定:verdict==expected ∧ top_layer==expected ∧ 每个 must_hit 命中(entity+action)∧
  无 must_not_hit。
- 输出矩阵:id | suite | 期望 | 实际 | ✓/✗ | top_layer | latency | 命中规则。
- 末尾按套件汇总:通过率 + 套件2 误报数(须 0)+ 套件1 漏拦数(须 0)。
- **不手写实测数字**;矩阵即实测。

L3 缺席口径(§9):离线无 Presidio 时,expected.top_layer=="L3" 且结果 notes 标了
"L3 skipped" 的用例,记为 SKIP(L3-ABSENT),既不判 PASS 也不计入套件1 漏拦——
基础设施缺失不应污染引擎正确性判定。带 Presidio 跑时这些用例正常参与判定。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# 允许 `python tests/run_offline.py` 直接跑(把 engine/ 加入 path)
_ENGINE_ROOT = Path(__file__).resolve().parent.parent
if str(_ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_ENGINE_ROOT))

from dlp.engine import DLPEngine, EngineConfig  # noqa: E402
from dlp.types import InjectionPoint  # noqa: E402

FIXTURE_DIR = _ENGINE_ROOT / "tests" / "fixtures"

_IP = {
    "prompt": InjectionPoint.PROMPT,
    "mcp": InjectionPoint.MCP,
    "flowback": InjectionPoint.FLOWBACK,
    "egress": InjectionPoint.EGRESS,
}

# ANSI(--no-color 关闭)
_C = {"ok": "\033[32m", "bad": "\033[31m", "skip": "\033[33m", "dim": "\033[2m", "z": "\033[0m"}


def _paint(s: str, key: str, color: bool) -> str:
    return f"{_C[key]}{s}{_C['z']}" if color else s


class Case:
    __slots__ = ("id", "suite", "ip", "content", "kind", "session_window",
                 "expected", "invariants", "verify_point", "notes_expected")

    def __init__(self, d: dict):
        self.id = d["id"]
        self.suite = d["suite"]
        self.ip = _IP[d.get("injection_point", "prompt")]
        self.content = d["content"]
        self.kind = d.get("content_kind", "text")
        self.session_window = d.get("session_window")
        self.expected = d["expected"]
        self.invariants = d.get("invariants", [])
        self.verify_point = d.get("verify_point", "")
        self.notes_expected = d.get("notes_expected", [])


def _l3_absent(result) -> bool:
    return any("L3 skipped" in n for n in result.notes)


def _hit_matches(hits, want: dict) -> bool:
    """must_hit / must_not_hit 元素匹配:entity 必匹配;若给了 action 也要匹配。"""
    we, wa = want.get("entity"), want.get("action")
    for h in hits:
        if we is not None and h.entity != we:
            continue
        if wa is not None and h.action.value != wa:
            continue
        return True
    return False


def evaluate(case: Case, result) -> tuple[str, list[str]]:
    """返回 (status, reasons)。status ∈ {'pass','fail','skip'}。"""
    exp = case.expected
    reasons: list[str] = []

    # L3 缺席:仅当该用例期望就是靠 L3 定裁决(top_layer==L3)时豁免
    if exp.get("top_layer") == "L3" and _l3_absent(result) and result.verdict.value == "pass":
        return "skip", ["L3 缺席(离线无 Presidio),按 §9 豁免——需带 Presidio 复跑"]

    if result.verdict.value != exp["verdict"]:
        reasons.append(f"verdict 期望 {exp['verdict']} 实际 {result.verdict.value}")

    exp_top = exp.get("top_layer")
    act_top = result.top_layer.value if result.top_layer else None
    if exp_top != act_top:
        reasons.append(f"top_layer 期望 {exp_top} 实际 {act_top}")

    for want in exp.get("must_hit", []):
        if not _hit_matches(result.hits, want):
            reasons.append(f"缺 must_hit {want}")

    for nono in exp.get("must_not_hit", []):
        if _hit_matches(result.hits, nono):
            reasons.append(f"命中了 must_not_hit {nono}(误报)")

    return ("pass" if not reasons else "fail"), reasons


def run(color: bool = True, only_suite: int | None = None, verbose: bool = False) -> int:
    cfg = EngineConfig()  # 默认 run_l3_on_all_variants=True;离线 Presidio 不可达会走缺席分支
    eng = DLPEngine(cfg)

    # 载入顺序:套件2(误报基线)优先,再套件1(金标准),再 3/4/5/6
    order = [2, 1, 3, 4, 5, 6]
    if only_suite:
        order = [only_suite]

    rows: list[tuple] = []
    summary: dict[int, dict] = {}
    missing_files: list[str] = []

    for s in order:
        fp = FIXTURE_DIR / f"suite{s}.json"
        if not fp.exists():
            missing_files.append(fp.name)
            continue
        cases = [Case(d) for d in json.loads(fp.read_text(encoding="utf-8"))]
        agg = summary.setdefault(s, {"pass": 0, "fail": 0, "skip": 0, "total": 0,
                                     "fp": 0, "miss": 0})
        for c in cases:
            run_l4 = (s == 6)
            result = eng.scan(
                c.content, injection_point=c.ip,
                run_async_l4=run_l4, session_window=c.session_window,
            )
            status, reasons = evaluate(c, result)
            agg["total"] += 1
            agg[status] += 1

            # 套件2 误报:期望 pass 却被拦/脱敏,或命中 must_not_hit
            if s == 2 and status == "fail":
                if any("误报" in r or "verdict" in r for r in reasons):
                    agg["fp"] += 1
            # 套件1 漏拦:期望 block/redact 却 pass
            if s == 1 and status == "fail" and result.verdict.value == "pass" \
                    and c.expected["verdict"] != "pass":
                agg["miss"] += 1

            hit_rules = ",".join(sorted({h.rule for h in result.hits})) or "-"
            lat = result.latency_ms.get("total", 0.0)
            rows.append((c.id, s, c.expected["verdict"],
                         result.verdict.value, status,
                         result.top_layer.value if result.top_layer else "-",
                         f"{lat:.2f}", hit_rules, reasons, result))

    # ---- 打印矩阵 ----
    print("=" * 100)
    print(f"{'ID':<9}{'St':<4}{'期望':<8}{'实际':<8}{'✓':<3}{'top':<6}{'ms':>8}  命中规则")
    print("-" * 100)
    for (cid, s, exp_v, act_v, status, top, lat, rules, reasons, result) in rows:
        mark = {"pass": "✓", "fail": "✗", "skip": "~"}[status]
        key = {"pass": "ok", "fail": "bad", "skip": "skip"}[status]
        line = (f"{cid:<9}{s:<4}{exp_v:<8}{act_v:<8}"
                f"{_paint(mark, key, color):<3}{top:<6}{lat:>8}  {rules[:40]}")
        print(line)
        if status == "fail":
            for r in reasons:
                print(f"           {_paint('· ' + r, 'bad', color)}")
            if verbose:
                for h in result.hits:
                    print(f"             hit: {h.layer.value} {h.rule} {h.entity} "
                          f"{h.action.value} src={h.source} fp={h.field_path}")
        elif status == "skip":
            print(f"           {_paint('· ' + reasons[0], 'skip', color)}")

    # ---- 汇总 ----
    print("=" * 100)
    print("套件汇总(顺序:套件2 基线 → 套件1 金标准 → 3/4/5/6):")
    grand = {"pass": 0, "fail": 0, "skip": 0, "total": 0}
    for s in order:
        if s not in summary:
            continue
        a = summary[s]
        for k in grand:
            grand[k] += a[k]
        rate = (a["pass"] / a["total"] * 100) if a["total"] else 0.0
        extra = ""
        if s == 2:
            fp_txt = _paint(str(a['fp']), "ok" if a["fp"] == 0 else "bad", color)
            extra = f"  误报数={fp_txt}(须 0)"
        if s == 1:
            miss_txt = _paint(str(a['miss']), "ok" if a["miss"] == 0 else "bad", color)
            extra = f"  漏拦数={miss_txt}(须 0)"
        print(f"  套件{s}: {a['pass']}/{a['total']} 通过 "
              f"({rate:.0f}%)  fail={a['fail']} skip={a['skip']}{extra}")

    print("-" * 100)
    gr = (grand["pass"] / grand["total"] * 100) if grand["total"] else 0.0
    print(f"  合计: {grand['pass']}/{grand['total']} ({gr:.0f}%)  "
          f"fail={grand['fail']} skip(L3缺席)={grand['skip']}")

    if missing_files:
        print(_paint(f"\n⚠ 缺 fixture 文件: {', '.join(missing_files)}"
                     f"(后台 agent 生成后重跑)", "skip", color))

    # 退出码:硬红线 —— 套件2 误报>0 或 套件1 漏拦>0 或有 fail → 非 0
    hard_fail = grand["fail"] > 0
    if 2 in summary and summary[2]["fp"] > 0:
        hard_fail = True
    if 1 in summary and summary[1]["miss"] > 0:
        hard_fail = True
    return 1 if (hard_fail or missing_files) else 0


def main():
    ap = argparse.ArgumentParser(description="DLP 离线单测 harness(§8)")
    ap.add_argument("--suite", type=int, default=None, help="只跑某套件(1-6)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--verbose", "-v", action="store_true", help="失败项打印 hits 详情")
    args = ap.parse_args()
    sys.exit(run(color=not args.no_color, only_suite=args.suite, verbose=args.verbose))


if __name__ == "__main__":
    main()
