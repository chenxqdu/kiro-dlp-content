#!/usr/bin/env python3
"""阶段3 压测(03 文档 §5/§6):网关端到端 RTT 开/关 DLP 对比 + 并发吞吐。

设计:
- 上游不打真模型(排除 Bedrock 延迟噪声/费用):payload 用固定短 prompt 打
  /chat/completions,模型仍是 Bedrock llama-3.1-8b(max_tokens=1)——上游耗时相同,
  开/关 DLP 的差值即 hook 成本。
- 三档 payload:clean-短(~50 tok)、clean-长(~2000 tok 无敏感)、redact 型(含 PII)。
- 并发:threading,c ∈ {1, 4, 8, 16},每档 n 次,统计 p50/p95。
用法:python3 bench_gateway.py --key $KEY [--base-url http://localhost:4000] [--n 30]
输出 JSON 行,供报告汇总。
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import statistics
import time
import urllib.error
import urllib.request

CLEAN_SHORT = "Explain what a hash map is in one sentence."
CLEAN_LONG = ("The quick brown fox jumps over the lazy dog. " * 150
              + "Summarize the above in one sentence.")
REDACT_PII = ("工单:客户李娜(Li Na)反馈登录异常,联系邮箱 lina@corpmail.cn,"
              "手机 +86 138 1234 5678,地址上海市浦东新区。请起草英文回复。")


def one_call(base_url: str, key: str, model: str, prompt: str) -> tuple[float, int]:
    payload = json.dumps({
        "model": model, "max_tokens": 1,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        f"{base_url}/chat/completions", data=payload, method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"})
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            resp.read()
            return (time.perf_counter() - t0) * 1000, resp.status
    except urllib.error.HTTPError as e:
        e.read()
        return (time.perf_counter() - t0) * 1000, e.code


def bench(base_url, key, model, prompt, n, conc):
    lats, errs = [], 0
    t_wall = time.perf_counter()
    with cf.ThreadPoolExecutor(max_workers=conc) as ex:
        futs = [ex.submit(one_call, base_url, key, model, prompt) for _ in range(n)]
        for f in futs:
            ms, status = f.result()
            if status == 200:
                lats.append(ms)
            else:
                errs += 1
    wall = time.perf_counter() - t_wall
    if not lats:
        return {"error": "all_failed", "errs": errs}
    lats.sort()
    return {
        "n_ok": len(lats), "errs": errs, "conc": conc,
        "p50_ms": round(statistics.median(lats), 1),
        "p95_ms": round(lats[max(0, int(len(lats) * 0.95) - 1)], 1),
        "mean_ms": round(statistics.fmean(lats), 1),
        "qps": round(len(lats) / wall, 2),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://localhost:4000")
    ap.add_argument("--key", required=True)
    ap.add_argument("--model", default="llama-3.1-8b")
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--label", default="dlp-on", help="dlp-on / dlp-off(关 guardrail 后跑)")
    args = ap.parse_args()

    cases = [("clean_short", CLEAN_SHORT), ("clean_long", CLEAN_LONG), ("redact_pii", REDACT_PII)]
    for conc in (1, 4, 8, 16):
        for name, prompt in cases:
            r = bench(args.base_url, args.key, args.model, prompt, args.n, conc)
            r.update({"case": name, "label": args.label})
            print(json.dumps(r, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
