#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
"""RAG embedding 单发延迟探针:对 /rag/query 计时(corpus 极小,cosine 可忽略,端到端≈embedding)。"""
import json, os, time, urllib.request, sys
URL = os.environ.get("RAG_URL", "http://127.0.0.1:8081/rag/query")
TAG = os.environ.get("TAG", "?")
texts = ["int main(){int a,b;scanf(\"%d%d\",&a,&b);printf(\"%d\",a+b);return 0;}",
         "def quicksort(a):\n    return a if len(a)<2 else quicksort([x for x in a[1:] if x<a[0]])+[a[0]]+quicksort([x for x in a[1:] if x>=a[0]])",
         "风控评分 risk_score = 0.3*逾期 + 0.7*额度,阈值 0.65 触发人工复核"]
def q(t):
    data=json.dumps({"text":t}).encode()
    req=urllib.request.Request(URL,data=data,headers={"Content-Type":"application/json"},method="POST")
    t0=time.perf_counter()
    with urllib.request.urlopen(req,timeout=30) as r: r.read()
    return (time.perf_counter()-t0)*1000
q(texts[0])  # warm
ms=[]
for _ in range(10):
    for t in texts: ms.append(q(t))
ms.sort()
p=lambda k: ms[min(len(ms)-1,int(len(ms)*k))]
print(json.dumps({"tag":TAG,"n":len(ms),"p50_ms":round(p(.5),1),"p95_ms":round(p(.95),1),
                  "min_ms":round(ms[0],1),"max_ms":round(ms[-1],1),
                  "note":"端到端 /rag/query(embed+corpus余弦,corpus 极小 cosine 可忽略);GPU 型号见同目录 env.txt"},ensure_ascii=False))
