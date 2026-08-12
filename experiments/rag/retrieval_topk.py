#!/usr/bin/env python3
#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
"""top-1 检索准确率锚（防 AP=1.000 饱和，§8.2 待测项 5 配套）。

问题：小评测集上强模型的 AP 容易饱和到 1.000，两个模型都 1.000 时 AP 无法分辨差距。
解法：从 threshold_sweep.py 已产出的 sweep JSON 的 per_case 里，对每条正例(label==1)
检查 top-1 命中是否正确（matched_doc == src_doc）——这是**非饱和**的检索准确率锚：
即使 AP=1.000，top-1 也可能因为「命中到别的登记文档」而 <1。

统计口径：
- top-1 准确率 = 正例中 matched_doc==src_doc 的比例，附 Wilson 95% 置信区间
  （小样本下比正态近似稳，n≈30 时区间宽是事实、如实报告）。
- 若 sweep 的 AP==1.0（饱和），补报 exact-binomial「三倍律」：0 失败观测时
  真实失败率 95% 上界 ≈ 3/n → AP/召回下界 ≈ 1 - 3/n，避免把 1.000 读成"证明完美"。

纯 CPU 后处理，零新增 RAG 服务调用；不修改 threshold_sweep.py（保历史结果口径不变）。

用法:
  python3 retrieval_topk.py --sweep results-X/sweep_f2llm_codenet-py.json \
      --sweep results-X/sweep_bge-m3_codenet-py.json --out results-X/retrieval_topk.json
"""
from __future__ import annotations

import argparse
import json
import math
import os


def wilson_ci(k: int, n: int, z: float = 1.959964) -> tuple:
    """Wilson score 95% 区间。"""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, center - half), min(1.0, center + half))


def analyze(sweep_path: str) -> dict:
    with open(sweep_path, encoding="utf-8") as fh:
        sw = json.load(fh)
    pos = [c for c in sw["per_case"] if c["label"] == 1]
    hits = [c for c in pos if c.get("matched_doc") and c["matched_doc"] == c.get("src_doc")]
    misses = [{"id": c["id"], "src_doc": c.get("src_doc"), "matched_doc": c.get("matched_doc"),
               "max_sim": c["max_sim"]} for c in pos if c not in hits]
    n, k = len(pos), len(hits)
    lo, hi = wilson_ci(k, n)
    out = {
        "sweep_file": os.path.basename(sweep_path),
        "n_pos": n, "top1_hits": k,
        "top1_accuracy": round(k / n, 4) if n else None,
        "wilson_95ci": [round(lo, 4), round(hi, 4)],
        "average_precision": sw.get("average_precision"),
        "misses": misses,
    }
    # AP 饱和 → 补三倍律下界（0 失败观测的 95% 失败率上界 3/n）
    if sw.get("average_precision") == 1.0:
        n_all = sw.get("n_cases") or n
        out["ap_saturated"] = True
        out["rule_of_three_note"] = (
            f"AP=1.000 为小样本饱和值：n={n_all} 条全对时，真实错误率 95% 上界≈3/{n_all}"
            f"={3 / n_all:.3f}，即 AP/召回真实下界≈{1 - 3 / n_all:.3f}，不可读作'证明完美'。")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sweep", action="append", required=True,
                    help="threshold_sweep.py 产出的 sweep JSON（可多次传入并列对比）")
    ap.add_argument("--out", default="retrieval_topk.json")
    args = ap.parse_args()

    results = [analyze(p) for p in args.sweep]
    out = {"note": ("top-1 检索准确率(matched_doc==src_doc) + Wilson 95% CI，防 AP 饱和锚；"
                    "从 sweep per_case 纯后处理，零新增服务调用"),
           "models": results}
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=2)

    print("== top-1 检索准确率（正例 matched_doc==src_doc）==")
    for r in results:
        line = (f"  {r['sweep_file']:<40} top1={r['top1_hits']}/{r['n_pos']}"
                f"={r['top1_accuracy']}  Wilson95%={r['wilson_95ci']}  AP={r['average_precision']}")
        print(line)
        if r.get("ap_saturated"):
            print(f"    ⚠ {r['rule_of_three_note']}")
        for m in r["misses"]:
            print(f"    ✗ {m['id']}: 期望 {m['src_doc']} 实际 {m['matched_doc']} (sim={m['max_sim']:.4f})")
    print(f"→ {args.out}")


if __name__ == "__main__":
    main()
