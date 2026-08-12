#!/usr/bin/env python3
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
"""低延迟增强对照(§8.1 H.3):精简输出 prompt(去长 reason)vs 完整契约,
测同模型 vLLM serving 单发延迟能压到多少。数字全取自机器。"""
import json, time, urllib.request, sys
from pathlib import Path
URL="http://127.0.0.1:8000/v1/chat/completions"; MODEL="Qwen/Qwen3-4B-Instruct-2507"
# 精简:只要 sensitive+category,reason 限 8 字内 → 大幅减输出 token
SLIM=('You are a corporate data-leak classifier. Decide if content exposes company '
 'sensitive info. Categories: proprietary-source, proprietary-business-logic, '
 'proprietary_tech, business_strategy, financial_nonpublic, none. Answer ONLY compact '
 'JSON, no prose: {"sensitive":true|false,"category":"...","confidence":0-1}. '
 'No "reason" field.\n\nCONTENT:\n')
def call(content, max_tok):
    p=json.dumps({"model":MODEL,"messages":[{"role":"user","content":SLIM+content[:4000]}],
        "max_tokens":max_tok,"temperature":0.0}).encode()
    r=urllib.request.Request(URL,data=p,headers={"Content-Type":"application/json"},method="POST")
    t0=time.perf_counter()
    with urllib.request.urlopen(r,timeout=30) as resp: d=json.loads(resp.read())
    ms=(time.perf_counter()-t0)*1000
    out=d["choices"][0]["message"]["content"]; ct=d["usage"]["completion_tokens"]
    cat=None
    try:
        import re; j=json.loads(re.search(r"\{.*\}",out,re.S).group(0))
        cat=j.get("category") if j.get("sensitive") else None
        if cat=="none": cat=None
    except Exception: pass
    return cat, ms, ct
cases=json.loads(Path(sys.argv[1]).read_text())
call("warmup",32)
allms=[]; ct_all=[]; exact=0; rows=[]
for c in cases:
    exp=c["expected"].get("async_l4_category"); lat=[]; got=None; cts=[]
    for _ in range(8):
        got,ms,ct=call(c["content"],64); lat.append(ms); cts.append(ct)
    lat.sort(); allms+=lat; ct_all+=cts
    norm=lambda x:(x or "").replace("_","-")
    ok=(norm(got)==norm(exp)) or (exp is None and got is None); exact+=ok
    rows.append((c["id"],exp,got,ok,round(lat[len(lat)//2],1),cts[len(cts)//2]))
allms.sort(); p=lambda k:allms[min(len(allms)-1,int(len(allms)*k))]
print(f"== Qwen3-4B vLLM 精简输出(去reason,max_tokens=64) ==")
print(f"  类别命中: {exact}/{len(cases)}")
print(f"  单发延迟(ms): p50={round(p(.5),1)} p95={round(p(.95),1)} min={round(allms[0],1)} max={round(allms[-1],1)}")
print(f"  输出token中位: {sorted(ct_all)[len(ct_all)//2]}")
for r in rows: print(f"    {'✓' if r[3] else '✗'} {r[0]:<7} 期望={r[1]} 实际={r[2]} p50={r[4]}ms ct={r[5]}")
out={"backend":"vllm-slim","model":MODEL,"category_exact":f"{exact}/{len(cases)}",
 "latency_ms":{"p50":round(p(.5),1),"p95":round(p(.95),1),"min":round(allms[0],1),"max":round(allms[-1],1)},
 "completion_tokens_median":sorted(ct_all)[len(ct_all)//2],
 "note":"精简输出(无reason字段,max_tokens=64),vLLM serving,CUDA graph;GPU 型号见同目录 env.txt;对照完整契约版"}
Path(sys.argv[2]).write_text(json.dumps(out,ensure_ascii=False,indent=2))
print("→",sys.argv[2])
