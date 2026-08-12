#!/usr/bin/env python3
#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
"""从 POJ-104 语义克隆数据集派生 RAG 评测小集（改进 B，§8.2 代码克隆）。

POJ-104（google/code_x_glue_cc_clone_detection_poj104，CodeXGLUE，C-UDA 许可）：
每条 {id, code, label}，label=题目编号(1..104)，**同 label = 语义等价（Type-4 克隆）**——
即"同一题的不同实现"，正是"改写代码"要检测的场景。取代有 93% 误标问题的 BigCloneBench
（arXiv:2505.04311）。

派生逻辑（对齐现有 corpus/eval schema，复用 rag_service.py + threshold_sweep.py）：
- 选 N 个题目（problem/label）。每题选 1 条提交作【登记机密】→ poj104_corpus.jsonl
  （{doc_id=poj-<label>, chunk_id, text=code}）。
- 每题另选 K 条同题提交作【改写正例】(label=1, src_doc=poj-<label>, rewrite_level=poj-t4)；
- 从【其它题】各选提交作【负例】(label=0)——不同题=语义不同，不该命中。
- 产出 poj104_eval.jsonl（{id,label,src_doc,rewrite_level,text}）。

★ 数据集运行时下载、不入 git（体积+许可）；只产出派生的小评测文件 + 后续指标。
★ 英文 C/C++ 代码，与中文业务机密自建集【域差大】→ 评测时分层报告、绝不与中文集平均。

用法（在能联网下 HF datasets 的机器上，如 g5）：
  python3 build_poj104_eval.py --n-problems 10 --pos-per 3 --neg-total 20 \
    --out-corpus data/poj104_corpus.jsonl --out-eval data/poj104_eval.jsonl
"""
from __future__ import annotations

import argparse
import json
import os


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-problems", type=int, default=10, help="选几个题目建库")
    ap.add_argument("--pos-per", type=int, default=3, help="每题几条改写正例")
    ap.add_argument("--neg-total", type=int, default=20, help="负例总数（来自其它题）")
    ap.add_argument("--split", default="train", help="POJ-104 split（train/validation/test）")
    ap.add_argument("--out-corpus", default="data/poj104_corpus.jsonl")
    ap.add_argument("--out-eval", default="data/poj104_eval.jsonl")
    ap.add_argument("--max-code-chars", type=int, default=2000, help="截断超长代码，控 embedding 成本")
    args = ap.parse_args()

    from datasets import load_dataset
    ds = load_dataset("google/code_x_glue_cc_clone_detection_poj104", split=args.split)
    # 字段名兼容：CodeXGLUE 版通常是 {id, code, label}
    cols = ds.column_names
    code_key = "code" if "code" in cols else ("func" if "func" in cols else cols[1])
    label_key = "label" if "label" in cols else cols[-1]

    # 按 label 分组（保序、确定性，不用随机——可复现）
    by_label: dict = {}
    for row in ds:
        lb = str(row[label_key])
        by_label.setdefault(lb, []).append(row[code_key][: args.max_code_chars])
    # 选提交数最多的前 N 个题目（确保每题有足够正例）
    labels = sorted(by_label, key=lambda k: (-len(by_label[k]), k))[: args.n_problems]

    corpus, evals = [], []
    for lb in labels:
        subs = by_label[lb]
        doc_id = f"poj-{lb}"
        corpus.append({"doc_id": doc_id, "chunk_id": "0", "text": subs[0]})  # 登记机密=首条
        for i, code in enumerate(subs[1 : 1 + args.pos_per]):                # 同题其余=改写正例
            evals.append({"id": f"P-{doc_id}-{i}", "label": 1, "src_doc": doc_id,
                          "rewrite_level": "poj-t4", "text": code})
    # 负例：从库外题目轮流取，直到 neg_total
    other = [lb for lb in by_label if lb not in labels]
    ni = 0
    while len([e for e in evals if e["label"] == 0]) < args.neg_total and other:
        lb = other[ni % len(other)]
        pool = by_label[lb]
        idx = (ni // len(other))
        if idx < len(pool):
            evals.append({"id": f"N-{lb}-{idx}", "label": 0, "src_doc": None,
                          "rewrite_level": "poj-negative", "text": pool[idx][: args.max_code_chars]})
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
    print(f"✓ POJ-104 派生：corpus={len(corpus)} 题（登记机密）| eval 正例={npos} 负例={nneg}")
    print(f"  corpus → {args.out_corpus}")
    print(f"  eval   → {args.out_eval}")
    print(f"  口径：同题=Type-4 语义克隆(改写正例)，异题=负例；英文 C/C++，与中文自建集分层不平均。")


if __name__ == "__main__":
    main()
