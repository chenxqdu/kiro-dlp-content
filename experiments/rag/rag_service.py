#!/usr/bin/env python3
#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
"""VPC-local RAG 相似度检索服务(L3.7 后端)——在 GPU 机上跑,引擎侧经 urllib 调。

职责:
  1. 加载一个 sentence-transformers 嵌入模型(GPU),把【已登记机密语料】编码成矩阵(L2 归一化)。
  2. HTTP POST /rag/query {"text","top_k"} → 对 query 编码、算与语料的余弦、返回 top-k + max_similarity。
  3. GET /health → {"status":"ok","model":...,"corpus":N}。

★ 精确 numpy 余弦(不用 faiss/ANN):DLP 不容忍 ANN 漏召回,语料几百~几千条时暴力矩阵乘即毫秒级。
★ 机密语料库(embedding 矩阵)只留在本 VPC 内 GPU 机内存 —— 符合 §6.4 风险4(向量库是敏感资产)。
★ 与引擎契约:响应只回 doc_id/chunk_id/score(相似度分),绝不回语料原文片段。

用法(g5 上):
  MODEL=BAAI/bge-m3 CORPUS=/home/ubuntu/corpus.jsonl python3 rag_service.py --port 8081
环境变量:
  MODEL   嵌入模型(默认 BAAI/bge-m3);对照可切 jinaai/jina-embeddings-v2-base-code、
          sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2
  CORPUS  机密语料 JSONL,每行 {"doc_id","chunk_id","text"};缺则空库(仅供探活)
  HF_ENDPOINT  hf-mirror 加速(默认沿用环境)
"""
from __future__ import annotations

import argparse
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import numpy as np

_MODEL_NAME = os.environ.get("MODEL", "BAAI/bge-m3")
_CORPUS_PATH = os.environ.get("CORPUS", "").strip()
_TRUST_REMOTE = os.environ.get("TRUST_REMOTE_CODE", "0") in ("1", "true", "yes")

# 延迟 import(torch/ST 重),便于 --help 快速返回。
_model = None
_corpus_meta: list[dict] = []   # [{doc_id, chunk_id}]
_corpus_mat: "np.ndarray | None" = None   # (N, dim) L2 归一化


def _load_model():
    global _model
    from sentence_transformers import SentenceTransformer
    import torch
    dev = "cuda" if torch.cuda.is_available() else "cpu"
    _model = SentenceTransformer(_MODEL_NAME, device=dev, trust_remote_code=_TRUST_REMOTE)
    return dev


def _encode(texts: list[str]) -> "np.ndarray":
    # normalize_embeddings=True → 输出已 L2 归一化,余弦=点积。
    v = _model.encode(texts, normalize_embeddings=True, convert_to_numpy=True,
                       batch_size=32, show_progress_bar=False)
    return np.asarray(v, dtype=np.float32)


def _load_corpus():
    global _corpus_meta, _corpus_mat
    if not _CORPUS_PATH or not os.path.exists(_CORPUS_PATH):
        _corpus_meta, _corpus_mat = [], None
        return 0
    rows = []
    with open(_CORPUS_PATH, encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            o = json.loads(ln)
            rows.append(o)
    if not rows:
        _corpus_meta, _corpus_mat = [], None
        return 0
    _corpus_meta = [{"doc_id": r.get("doc_id", f"d{i}"), "chunk_id": str(r.get("chunk_id", 0))}
                    for i, r in enumerate(rows)]
    _corpus_mat = _encode([r["text"] for r in rows])
    return len(rows)


def _query(text: str, top_k: int) -> dict:
    if _corpus_mat is None or not text.strip():
        return {"max_similarity": 0.0, "matches": []}
    q = _encode([text])[0]                       # (dim,)
    sims = _corpus_mat @ q                        # (N,) 余弦(均已归一化)
    k = min(top_k, len(sims))
    idx = np.argsort(-sims)[:k]
    matches = [{"doc_id": _corpus_meta[i]["doc_id"],
                "chunk_id": _corpus_meta[i]["chunk_id"],
                "score": round(float(sims[i]), 4)} for i in idx]
    return {"max_similarity": round(float(sims[idx[0]]), 4) if len(idx) else 0.0,
            "matches": matches}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, obj):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except BrokenPipeError:
            pass

    def do_GET(self):  # noqa: N802
        if self.path.split("?")[0] == "/health":
            self._send(200, {"status": "ok", "model": _MODEL_NAME, "corpus": len(_corpus_meta)})
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self):  # noqa: N802
        if self.path.split("?")[0] != "/rag/query":
            return self._send(404, {"error": "not_found"})
        try:
            n = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(n)) if n > 0 else {}
        except Exception:
            return self._send(400, {"error": "bad_request"})
        text = body.get("text", "")
        top_k = int(body.get("top_k", 5))
        t0 = time.perf_counter()
        out = _query(text, top_k)
        out["latency_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        self._send(200, out)

    def log_message(self, *a):  # 静音访问日志(避免记 query 原文)
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8081)
    ap.add_argument("--bind", default="0.0.0.0")
    args = ap.parse_args()
    print(f"[rag] loading model {_MODEL_NAME} ...", flush=True)
    dev = _load_model()
    n = _load_corpus()
    print(f"[rag] model on {dev}; corpus={n} chunks; listening {args.bind}:{args.port}", flush=True)
    ThreadingHTTPServer((args.bind, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
