#!/usr/bin/env python3
#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
"""VPC-local 小模型(vLLM)L4 语义分类：类别命中 + 单发延迟标定(§8.1)。

复用 engine 的 l4_semantic 分类 prompt/契约 + suite6 语料 + perf_counter 计时范式,
把后端从 Bedrock 换成【VPC-local vLLM】(env DLP_L4_BACKEND=vllm),对比 7B/14B 与
现有 Bedrock Qwen3-32B/Llama-8B 基线(方案一 §8.4:32B 4/4、8B 3/4;直连 193–564ms)。

用法(在能访问 vLLM :8000 的机器上,如 g5 本机或 DLP 主机):
  DLP_L4_BACKEND=vllm DLP_L4_VLLM_URL=http://127.0.0.1:8000/v1/chat/completions \
  DLP_L4_VLLM_MODEL=Qwen/Qwen2.5-7B-Instruct \
  python3 vllm_l4_latency.py --fixtures /path/to/suite6.json --out results/vllm_7b.json

★ vllm: 后端哨兵确认真命中(非静默回退启发式);数字全取自机器,无手写。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

# 复用 engine 的 l4_semantic(需 engine 在 path)
_ENGINE = Path(__file__).resolve().parents[2] / "engine"
if str(_ENGINE) not in sys.path:
    sys.path.insert(0, str(_ENGINE))
from dlp import l4_semantic  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures", default=str(_ENGINE / "tests/fixtures/suite6.json"))
    ap.add_argument("--out", default="vllm_l4.json")
    ap.add_argument("--repeat", type=int, default=5, help="每条测多次取分位")
    args = ap.parse_args()

    if os.environ.get("DLP_L4_BACKEND", "").lower() != "vllm":
        print("⚠ 未设 DLP_L4_BACKEND=vllm —— 本脚本专测 vLLM VPC-local 后端", file=sys.stderr)
        sys.exit(2)
    model = os.environ.get("DLP_L4_VLLM_MODEL", "Qwen/Qwen2.5-7B-Instruct")

    cases = json.loads(Path(args.fixtures).read_text(encoding="utf-8"))
    # warm-up
    l4_semantic.analyze("warmup 预热请求", use_bedrock=True)

    rows, all_ms = [], []
    exact = 0
    for c in cases:
        exp = c["expected"].get("async_l4_category")   # oracle;None=不该告警
        content = c["content"]
        lat = []
        got = None
        via = False
        for _ in range(args.repeat):
            t0 = time.perf_counter()
            alerts = l4_semantic.analyze(content, use_bedrock=True)
            lat.append((time.perf_counter() - t0) * 1000)
            got = alerts[0].category if alerts else None
            via = bool(alerts and alerts[0].model.startswith("vllm:"))
        lat.sort()
        all_ms.extend(lat)
        # 类别命中:命中类别==oracle,或都为 None(阴性对照)
        ok = (got == exp) or (exp is None and got is None)
        exact += ok
        rows.append({"id": c["id"], "expected": exp, "got": got, "via_vllm": via,
                     "hit": ok, "p50_ms": round(lat[len(lat)//2], 1),
                     "min_ms": round(lat[0], 1), "max_ms": round(lat[-1], 1)})

    all_ms.sort()
    p = lambda k: all_ms[min(len(all_ms)-1, int(len(all_ms)*k))]
    summary = {
        "backend": "vllm", "model": model, "fixtures": Path(args.fixtures).name,
        "n_cases": len(cases), "repeat": args.repeat,
        "category_exact": f"{exact}/{len(cases)}",
        "latency_ms": {"p50": round(p(.5), 1), "p95": round(p(.95), 1),
                       "p99": round(p(.99), 1), "min": round(all_ms[0], 1),
                       "max": round(all_ms[-1], 1)},
        "per_case": rows,
    }
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    Path(args.out).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"== vLLM L4 标定 {model} ==")
    print(f"  类别命中: {exact}/{len(cases)}  (对比基线 Bedrock Qwen3-32B 4/4、Llama-8B 3/4)")
    la = summary["latency_ms"]
    print(f"  单发延迟(ms): p50={la['p50']} p95={la['p95']} p99={la['p99']} min={la['min']} max={la['max']}")
    for r in rows:
        m = "✓" if r["hit"] else "✗"
        v = "" if r["via_vllm"] or r["got"] is None else " ⚠非vllm(回退?)"
        print(f"    {m} {r['id']:<8} 期望={r['expected']} 实际={r['got']} p50={r['p50_ms']}ms{v}")
    print(f"  → {args.out}")


if __name__ == "__main__":
    main()
