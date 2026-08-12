#!/usr/bin/env python3
#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
"""RAG 相似度拦截效果评测:阈值扫描 + PR/ROC + 分层报告(§8.2)。

对 eval.jsonl 每条 query 打 RAG 检索服务,取 max_similarity 作分数,label 作真值,
做二分类阈值扫描。DLP 类别极不平衡且更在意"少漏机密" → 主看 PR 曲线 + 高 recall 选阈值。

用法:
  RAG_URL=http://127.0.0.1:8081/rag/query python3 threshold_sweep.py \
    --eval data/eval.jsonl --out results-YYYYMMDD/sweep.json

输出:
  - 每条 (id,label,rewrite_level,src_doc,max_sim,matched_doc) → scores.jsonl
  - PR/ROC 曲线点 + AP + AUC(有 sklearn 用之,否则手写)
  - 按 rewrite_level 分层的命中情况
  - 推荐工作点(满足 recall 目标下 precision 最高的阈值)
全部数字取自 RAG 服务真实返回,无手写。RAG 服务不可达则明确报错退出,绝不伪造。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

RAG_URL = os.environ.get("RAG_URL", "http://127.0.0.1:8081/rag/query")


def _q(text: str, top_k: int = 5, timeout: float = 30.0) -> dict:
    payload = json.dumps({"text": text, "top_k": top_k}).encode("utf-8")
    req = urllib.request.Request(RAG_URL, data=payload,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _pr_manual(scores, labels):
    """无 sklearn 时手写 precision-recall + ROC 扫描。"""
    thrs = sorted(set(scores), reverse=True)
    pr, roc = [], []
    P = sum(labels)
    N = len(labels) - P
    for t in thrs:
        tp = sum(1 for s, y in zip(scores, labels) if s >= t and y == 1)
        fp = sum(1 for s, y in zip(scores, labels) if s >= t and y == 0)
        fn = P - tp
        prec = tp / (tp + fp) if (tp + fp) else 1.0
        rec = tp / P if P else 0.0
        fpr = fp / N if N else 0.0
        pr.append((t, prec, rec))
        roc.append((t, fpr, rec))
    # AP ≈ Σ (R_n − R_{n-1}) · P_n
    ap, prev_r = 0.0, 0.0
    for _, prec, rec in pr:
        ap += (rec - prev_r) * prec
        prev_r = rec
    return pr, roc, ap


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--eval", default="data/eval.jsonl")
    ap.add_argument("--out", default="sweep.json")
    ap.add_argument("--recall-target", type=float, default=1.0,
                    help="选阈值时要求的最低 recall(默认 1.0=不漏任何机密)")
    args = ap.parse_args()

    cases = [json.loads(l) for l in open(args.eval, encoding="utf-8") if l.strip()]
    # 探活
    try:
        _q("healthcheck", top_k=1)
    except (urllib.error.URLError, OSError, ValueError) as e:
        print(f"❌ RAG 服务不可达 {RAG_URL}: {e} —— 绝不伪造数字,退出", file=sys.stderr)
        sys.exit(2)

    rows = []
    for c in cases:
        r = _q(c["text"])
        matches = r.get("matches") or []
        rows.append({
            "id": c["id"], "label": c["label"],
            "rewrite_level": c.get("rewrite_level"), "src_doc": c.get("src_doc"),
            "max_sim": float(r.get("max_similarity", 0.0)),
            "matched_doc": matches[0]["doc_id"] if matches else None,
        })

    scores = [x["max_sim"] for x in rows]
    labels = [x["label"] for x in rows]

    try:
        from sklearn.metrics import (average_precision_score, precision_recall_curve,
                                      roc_auc_score, roc_curve)
        prec, rec, pr_thr = precision_recall_curve(labels, scores)
        fpr, tpr, roc_thr = roc_curve(labels, scores)
        ap = float(average_precision_score(labels, scores))
        auc = float(roc_auc_score(labels, scores))
        pr_points = [{"threshold": float(t), "precision": float(p), "recall": float(r)}
                     for p, r, t in zip(prec[:-1], rec[:-1], pr_thr)]
        roc_points = [{"threshold": float(t), "fpr": float(f), "tpr": float(tp)}
                      for f, tp, t in zip(fpr, tpr, roc_thr)]
        backend = "sklearn"
    except ImportError:
        pr, roc, ap = _pr_manual(scores, labels)
        auc = None
        pr_points = [{"threshold": t, "precision": p, "recall": r} for t, p, r in pr]
        roc_points = [{"threshold": t, "fpr": f, "tpr": tp} for t, f, tp in roc]
        backend = "manual"

    # 推荐工作点:满足 recall≥target 的候选里 precision 最高;并列取阈值最高(更保守)
    cand = [p for p in pr_points if p["recall"] >= args.recall_target]
    best = max(cand, key=lambda p: (p["precision"], p["threshold"])) if cand else None

    # 分层:按 rewrite_level 看正例命中(以 best 阈值,或未定阈值时报每条 sim)
    strat = {}
    for x in rows:
        lv = x["rewrite_level"] or "?"
        strat.setdefault(lv, {"label1": 0, "label0": 0, "sims": []})
        strat[lv]["label1" if x["label"] == 1 else "label0"] += 1
        strat[lv]["sims"].append(round(x["max_sim"], 4))

    out = {
        "rag_url": RAG_URL, "n_cases": len(rows), "n_pos": sum(labels), "n_neg": len(labels) - sum(labels),
        "metric_backend": backend, "average_precision": round(ap, 4),
        "roc_auc": round(auc, 4) if auc is not None else None,
        "recommended": best, "recall_target": args.recall_target,
        "pr_curve": pr_points, "roc_curve": roc_points,
        "per_case": rows, "stratified": strat,
    }
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=2)

    # 人读摘要
    print(f"== RAG 阈值扫描 ({backend}) ==")
    print(f"  cases={len(rows)} pos={sum(labels)} neg={len(labels)-sum(labels)}  AP={ap:.4f}"
          + (f"  ROC-AUC={auc:.4f}" if auc is not None else ""))
    if best:
        print(f"  推荐工作点: threshold={best['threshold']:.4f}  "
              f"precision={best['precision']:.3f} recall={best['recall']:.3f}"
              f"(recall≥{args.recall_target})")
    else:
        print(f"  ⚠ 无阈值能达到 recall≥{args.recall_target}(最高 recall<target),见曲线")
    print("  分层(rewrite_level → 正例数/负例数, 相似度):")
    for lv, d in sorted(strat.items()):
        print(f"    {lv:<14} pos={d['label1']} neg={d['label0']}  sims={sorted(d['sims'], reverse=True)}")
    print(f"  → 详见 {args.out}")


if __name__ == "__main__":
    main()
