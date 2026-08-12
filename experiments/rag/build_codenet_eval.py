#!/usr/bin/env python3
#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
"""从 Project CodeNet Python800 基准子集派生 RAG 评测小集（待测项 5，§8.2 跨语言代码克隆）。

Project CodeNet（IBM，NeurIPS 2021，arXiv:2105.12655，源码 Apache-2.0）：
Python800 基准子集 = 800 题 × 每题若干 Accepted Python 提交，**同题 = 语义等价（Type-4 克隆）**
——与 POJ-104 的 label 分组语义完全一致，官方明言可作 POJ-104 的替代/补充。
本轮用它回答：上轮 POJ-104（C/C++）上「代码嵌入 F2LLM 碾压通用 bge-m3」是否泛化到 Python。

数据源（HEAD 已验证可下）：
  主源  IBM DAX/COS 官方 Python800 子集 tarball（~29MB）:
    https://codait-cos-dax.s3.us.cloud-object-storage.appdomain.cloud/dax-project-codenet/1.0.0/Project_CodeNet_Python800.tar.gz
  结构  Project_CodeNet_Python800/<pXXXXX>/<sYYYY>.py —— 题目录/提交文件。
  （CodeS 论文的 figshare 分享镜像 API 403 不可程序化解析，弃用；许可同为 Apache-2.0。）

派生逻辑（与 build_poj104_eval.py 完全同构，对齐现有 corpus/eval schema，
复用 rag_service.py + threshold_sweep.py 零改动）：
- 选 N 个题目（提交数最多、确定性排序）。每题选 1 条提交作【登记机密】→ corpus
  （{doc_id=cn-py-<题目>, chunk_id, text=code}）。
- 每题另选 K 条同题提交作【改写正例】(label=1, src_doc, rewrite_level="codenet-py-t4")；
- 从【其它题】轮流取提交作【负例】(label=0, rewrite_level="codenet-py-negative")。

★ 原始数据集运行时下载、不入 git；只产出派生的小评测文件 + 后续指标。
★ 英文 Python 代码，与 POJ-104(C/C++)、中文自建集【三层分开报、绝不平均】。

用法（本地或 GPU 机均可，下载纯 CPU）：
  python3 build_codenet_eval.py --n-problems 10 --pos-per 3 --neg-total 20 \
    --out-corpus data/codenet_py_corpus.jsonl --out-eval data/codenet_py_eval.jsonl
可用 --tarball 指向已下载的 tar.gz 跳过下载。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tarfile
import urllib.request

DAX_URL = ("https://codait-cos-dax.s3.us.cloud-object-storage.appdomain.cloud/"
           "dax-project-codenet/1.0.0/Project_CodeNet_Python800.tar.gz")


def _download(url: str, dest: str) -> None:
    print(f"↓ 下载 {url}\n  → {dest}")
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
    with urllib.request.urlopen(req, timeout=120) as resp, open(dest, "wb") as fh:
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            fh.write(chunk)
    print(f"  ✓ {os.path.getsize(dest) / 1048576:.1f} MB")


def _load_by_problem(tarball: str, max_chars: int) -> dict:
    """遍历 tar 内 <problem>/<submission>.py，按题分组（保序、确定性）。

    ★ 必须顺序流式读取：gzip 流不支持随机寻址，先 getmembers() 排序再逐个
    extractfile() 会每次回卷重解压（O(n²)，24 万文件直接卡死）。
    这里按 tar 自然顺序读入 (文件名, 代码)，读完后在内存里排序保证确定性。
    """
    rows = []  # (member_name, prob, code)
    with tarfile.open(tarball, "r:gz") as tf:
        for m in tf:                    # 顺序迭代，单遍解压
            if not (m.isfile() and m.name.endswith(".py")):
                continue
            parts = m.name.split("/")
            if len(parts) < 2:
                continue
            f = tf.extractfile(m)
            if f is None:
                continue
            try:
                code = f.read().decode("utf-8", errors="replace")[:max_chars]
            finally:
                f.close()
            if code.strip():
                rows.append((m.name, parts[-2], code))  # 倒数第二级目录=题目 id
    rows.sort(key=lambda r: r[0])       # 事后排序 → 与 tar 内顺序无关，可复现
    by_prob: dict = {}
    for _, prob, code in rows:
        by_prob.setdefault(prob, []).append(code)
    return by_prob


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-problems", type=int, default=10, help="选几个题目建库")
    ap.add_argument("--pos-per", type=int, default=3, help="每题几条改写正例")
    ap.add_argument("--neg-total", type=int, default=20, help="负例总数（来自其它题）")
    ap.add_argument("--tarball", default="/tmp/codenet_py800.tar.gz",
                    help="Python800 tarball 路径（不存在则自动下载）")
    ap.add_argument("--out-corpus", default="data/codenet_py_corpus.jsonl")
    ap.add_argument("--out-eval", default="data/codenet_py_eval.jsonl")
    ap.add_argument("--max-code-chars", type=int, default=2000, help="截断超长代码，控 embedding 成本")
    args = ap.parse_args()

    if not os.path.exists(args.tarball):
        _download(DAX_URL, args.tarball)

    by_prob = _load_by_problem(args.tarball, args.max_code_chars)
    if not by_prob:
        print("❌ tarball 内未找到 <problem>/<submission>.py 结构 —— 绝不伪造，退出", file=sys.stderr)
        sys.exit(2)
    print(f"  共 {len(by_prob)} 题，提交总数 {sum(len(v) for v in by_prob.values())}")

    # 选提交数最多的前 N 个题目（确保每题有足够正例；确定性排序可复现）
    probs = sorted(by_prob, key=lambda k: (-len(by_prob[k]), k))[: args.n_problems]

    corpus, evals = [], []
    for pr in probs:
        subs = by_prob[pr]
        doc_id = f"cn-py-{pr}"
        corpus.append({"doc_id": doc_id, "chunk_id": "0", "text": subs[0]})  # 登记机密=首条
        for i, code in enumerate(subs[1: 1 + args.pos_per]):                 # 同题其余=改写正例
            evals.append({"id": f"P-{doc_id}-{i}", "label": 1, "src_doc": doc_id,
                          "rewrite_level": "codenet-py-t4", "text": code})
    # 负例：从库外题目轮流取，直到 neg_total
    other = sorted(pr for pr in by_prob if pr not in probs)
    ni = 0
    while len([e for e in evals if e["label"] == 0]) < args.neg_total and other:
        pr = other[ni % len(other)]
        pool = by_prob[pr]
        idx = ni // len(other)
        if idx < len(pool):
            evals.append({"id": f"N-{pr}-{idx}", "label": 0, "src_doc": None,
                          "rewrite_level": "codenet-py-negative", "text": pool[idx]})
        ni += 1
        if ni > len(other) * 50:
            break

    os.makedirs(os.path.dirname(args.out_corpus) or ".", exist_ok=True)
    with open(args.out_corpus, "w", encoding="utf-8") as fh:
        for r in corpus:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(args.out_eval, "w", encoding="utf-8") as fh:
        for r in evals:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    npos = sum(1 for e in evals if e["label"] == 1)
    nneg = sum(1 for e in evals if e["label"] == 0)
    print(f"✓ CodeNet Python800 派生：corpus={len(corpus)} 题（登记机密）| eval 正例={npos} 负例={nneg}")
    print(f"  corpus → {args.out_corpus}")
    print(f"  eval   → {args.out_eval}")
    print(f"  口径：同题=Type-4 语义克隆(改写正例)，异题=负例；英文 Python，与 POJ-104(C/C++)、中文自建集三层分开不平均。")


if __name__ == "__main__":
    main()
