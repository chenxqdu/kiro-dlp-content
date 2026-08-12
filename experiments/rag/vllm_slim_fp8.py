#!/usr/bin/env python3
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
"""FP8 / 换卡加速验证(§5.3 待测续):与 vllm_slim.py 完全同口径(SLIM 精简契约,
max_tokens=64,temperature=0,8 次重复取分位),仅模型/卡型可变——用于
① L40S 上 BF16(隔离换卡效应) ② L40S 上 FP8(官方 Qwen3-4B-Instruct-2507-FP8)。
数字全取自机器;MODEL/TAG 由环境变量注入,避免复制脚本导致口径漂移。"""
import json, os, time, urllib.request, sys
from pathlib import Path

URL = os.environ.get("VLLM_URL", "http://127.0.0.1:8000/v1/chat/completions")
MODEL = os.environ.get("MODEL", "Qwen/Qwen3-4B-Instruct-2507-FP8")
TAG = os.environ.get("TAG", "vllm-slim-fp8")
# 与 vllm_slim.py 逐字一致的精简契约 prompt
SLIM = ('You are a corporate data-leak classifier. Decide if content exposes company '
        'sensitive info. Categories: proprietary-source, proprietary-business-logic, '
        'proprietary_tech, business_strategy, financial_nonpublic, none. Answer ONLY compact '
        'JSON, no prose: {"sensitive":true|false,"category":"...","confidence":0-1}. '
        'No "reason" field.\n\nCONTENT:\n')


def call(content, max_tok):
    p = json.dumps({"model": MODEL,
                    "messages": [{"role": "user", "content": SLIM + content[:4000]}],
                    "max_tokens": max_tok, "temperature": 0.0}).encode()
    r = urllib.request.Request(URL, data=p, headers={"Content-Type": "application/json"},
                               method="POST")
    t0 = time.perf_counter()
    with urllib.request.urlopen(r, timeout=60) as resp:
        d = json.loads(resp.read())
    ms = (time.perf_counter() - t0) * 1000
    out = d["choices"][0]["message"]["content"]
    ct = d["usage"]["completion_tokens"]
    cat = None
    try:
        import re
        j = json.loads(re.search(r"\{.*\}", out, re.S).group(0))
        cat = j.get("category") if j.get("sensitive") else None
        if cat == "none":
            cat = None
    except Exception:
        pass
    return cat, ms, ct


cases = json.loads(Path(sys.argv[1]).read_text())
call("warmup", 32)
allms = []; ct_all = []; exact = 0; rows = []
for c in cases:
    exp = c["expected"].get("async_l4_category"); lat = []; got = None; cts = []
    for _ in range(8):
        got, ms, ct = call(c["content"], 64); lat.append(ms); cts.append(ct)
    lat.sort(); allms += lat; ct_all += cts
    norm = lambda x: (x or "").replace("_", "-")
    ok = (norm(got) == norm(exp)) or (exp is None and got is None); exact += ok
    rows.append((c["id"], exp, got, ok, round(lat[len(lat)//2], 1), cts[len(cts)//2]))
allms.sort(); p = lambda k: allms[min(len(allms)-1, int(len(allms)*k))]
print(f"== {TAG} model={MODEL} ==")
print(f"  类别命中: {exact}/{len(cases)}")
print(f"  单发延迟(ms): p50={round(p(.5),1)} p95={round(p(.95),1)} min={round(allms[0],1)} max={round(allms[-1],1)}")
print(f"  输出token中位: {sorted(ct_all)[len(ct_all)//2]}")
for r in rows:
    print(f"    {'✓' if r[3] else '✗'} {r[0]:<7} 期望={r[1]} 实际={r[2]} p50={r[4]}ms ct={r[5]}")
out = {"backend": TAG, "model": MODEL, "category_exact": f"{exact}/{len(cases)}",
       "latency_ms": {"p50": round(p(.5), 1), "p95": round(p(.95), 1),
                      "min": round(allms[0], 1), "max": round(allms[-1], 1)},
       "completion_tokens_median": sorted(ct_all)[len(ct_all)//2],
       "note": "精简输出契约与 vllm_slim.py 逐字一致(max_tokens=64,temp=0,每例8次);"
               "GPU 型号见同目录 env.txt;对照 L4 卡 BF16 的 695ms"}
Path(sys.argv[2]).write_text(json.dumps(out, ensure_ascii=False, indent=2))
print("→", sys.argv[2])
