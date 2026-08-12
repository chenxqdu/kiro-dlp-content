#!/usr/bin/env python3
#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
"""VPC-local 小模型 L4 延迟标定（transformers 直推，vLLM 起不来时的降级路径，§8.1）。

直接用 transformers AutoModelForCausalLM 加载 Qwen2.5-7B/14B（GPU），对 suite6 语料跑
与 engine.l4_semantic 相同的分类 prompt，测【类别命中 + 单发延迟】。不依赖 vLLM/flashinfer。

★ 口径诚实：transformers 直推【无 vLLM 的连续批处理/PagedAttention 优化】，单发延迟会
  【高于】同模型的 vLLM serving，是「延迟上界/量级参考」，不是生产 serving 数字。回填博客时明确标注。
★ 内容不出 VPC（本机 GPU 推理）——符合红线。

用法（g5 本机）：
  MODEL=Qwen/Qwen2.5-7B-Instruct python3 hf_l4_latency.py --fixtures suite6.json --out results/hf_7b.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

_PROMPT = (
    "You are a corporate data-leak classifier. The content below is about to be "
    "sent to an EXTERNAL cloud LLM. Decide if it exposes company-internal sensitive "
    "information. Categories: proprietary-source, proprietary-business-logic, "
    "proprietary_tech, business_strategy, financial_nonpublic, none. Generic/open-source "
    "algorithms, public knowledge, mundane requests are NOT sensitive. Answer strictly as "
    "JSON: {\"sensitive\":true|false,\"category\":\"...\",\"confidence\":0-1,\"reason\":\"...\"}"
    "\n\nCONTENT:\n"
)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures", required=True)
    ap.add_argument("--out", default="hf_l4.json")
    ap.add_argument("--repeat", type=int, default=3)
    args = ap.parse_args()
    model_id = os.environ.get("MODEL", "Qwen/Qwen2.5-7B-Instruct")

    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    t_load = time.perf_counter()
    tok = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForCausalLM.from_pretrained(model_id, torch_dtype=torch.float16, device_map="cuda")
    model.eval()
    load_s = time.perf_counter() - t_load
    print(f"[hf] loaded {model_id} in {load_s:.1f}s on {next(model.parameters()).device}", flush=True)

    def classify(content: str) -> tuple[str | None, float]:
        msgs = [{"role": "user", "content": _PROMPT + content[:2000]}]
        prompt_text = tok.apply_chat_template(msgs, add_generation_prompt=True, tokenize=False)
        enc = tok(prompt_text, return_tensors="pt").to("cuda")
        in_len = enc["input_ids"].shape[1]
        t0 = time.perf_counter()
        with torch.no_grad():
            out = model.generate(**enc, max_new_tokens=120, do_sample=False,
                                  pad_token_id=tok.eos_token_id)
        ms = (time.perf_counter() - t0) * 1000
        txt = tok.decode(out[0][in_len:], skip_special_tokens=True)
        cat = None
        try:
            d = json.loads(re.search(r"\{.*\}", txt, re.DOTALL).group(0))
            cat = d.get("category") if d.get("sensitive") else None
            if cat == "none":
                cat = None
        except Exception:
            pass
        return cat, ms

    cases = json.loads(Path(args.fixtures).read_text(encoding="utf-8"))
    classify("warmup")  # warm
    rows, all_ms, exact = [], [], 0
    for c in cases:
        exp = c["expected"].get("async_l4_category")
        lat, got = [], None
        for _ in range(args.repeat):
            got, ms = classify(c["content"])
            lat.append(ms)
        lat.sort(); all_ms.extend(lat)
        # 类别命中:归一化 - / _ 差异后比对（oracle 用 - ，模型可能回 _）
        norm = lambda x: (x or "").replace("_", "-")
        ok = norm(got) == norm(exp)
        exact += ok
        rows.append({"id": c["id"], "expected": exp, "got": got, "hit": ok,
                     "p50_ms": round(lat[len(lat)//2], 1)})
    all_ms.sort()
    p = lambda k: all_ms[min(len(all_ms)-1, int(len(all_ms)*k))]
    summary = {"backend": "transformers-direct", "model": model_id, "load_s": round(load_s, 1),
               "n_cases": len(cases), "repeat": args.repeat,
               "category_exact": f"{exact}/{len(cases)}",
               "latency_ms_generate": {"p50": round(p(.5), 1), "p95": round(p(.95), 1),
                                       "min": round(all_ms[0], 1), "max": round(all_ms[-1], 1)},
               "per_case": rows,
               "note": "transformers 直推,无 vLLM 批处理优化 → 单发延迟是量级上界,非生产 serving 数字"}
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    Path(args.out).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    la = summary["latency_ms_generate"]
    print(f"== {model_id} (transformers 直推) ==")
    print(f"  类别命中: {exact}/{len(cases)}  单发 generate 延迟(ms): p50={la['p50']} p95={la['p95']} max={la['max']}")
    for r in rows:
        print(f"    {'✓' if r['hit'] else '✗'} {r['id']:<8} 期望={r['expected']} 实际={r['got']} p50={r['p50_ms']}ms")
    print(f"  → {args.out}")


if __name__ == "__main__":
    main()
