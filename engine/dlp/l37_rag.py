#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
"""L3.7 RAG 相似度检索(语义 EDM,SPEC §5-L3.7)—— 秒内,同步/半同步。

补 L3.5(精确 EDM)与 L4(通用 LLM)之间的空档:把企业【已登记机密语料】预先 embedding
建向量库,请求内容 embedding 后算最近邻余弦相似度,超阈值即命中。比 L3.5 的精确串匹配宽
(抓同义改写/变量改名/中英混排/结构重排),比 L4 的无参照泛化判断确定(锚定真实私有语料)。

★ 红线:embedding 模型 + 向量库必须【VPC-local】(自托管 GPU + TEI/vLLM)。引擎侧【零重依赖】——
  与 l3_presidio.py 同构:只用 urllib 调独立 RAG 检索服务,numpy/embedding 全在服务端。

★ 不可达语义(同 L3):返回 (hits, status),status ∈ {"ok","unreachable"}。
  服务不可达/超时/坏响应 → ([], "unreachable"),【绝不静默 pass】,交引擎标注 "L3.7 skipped"
  由上层决定 fail-closed;离线无服务时 run_layers/run_offline 据此 SKIP,不算 fail。

★ 脱敏:命中 Hit 的 matched 只放【非原文相似度标签】(sim=.. doc=..),绝不放 query 原文或
  语料片段——与 L4 合成 Hit(engine.py 第 6 步)一致,守 server._safe_rules / sink 契约。
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .types import Hit, Layer, Verdict

# 容器内由 compose 注入 RAG_SERVICE_URL;指向 VPC-local 检索服务(g6 上 TEI/vLLM embedding
# + numpy 余弦检索同置)。默认本机回环仅为占位,真实部署必须显式注入。
# ★ 每次 scan() 读 env(而非模块级冻结常量):避免 import 顺序坑——调用方(如 server.py)
#   在 import dlp 之后才设 RAG_SERVICE_URL 时仍能生效。
_DEFAULT_URL = "http://127.0.0.1:8081/rag/query"
# 模块级常量仅供 run_layers 的 _rag_up() 探活拼 /health 用;真实调用走 _service_url()。
RAG_SERVICE_URL = os.environ.get("RAG_SERVICE_URL", _DEFAULT_URL)


def _service_url() -> str:
    return os.environ.get("RAG_SERVICE_URL", _DEFAULT_URL)

# 命中动作:语义相似度无"片段可遮蔽",REDACT 无意义 → 默认 BLOCK。
# 可由 EngineConfig.l37_action 覆盖(调用方传入)。
_DEFAULT_ACTION = Verdict.BLOCK


def _call_service(text: str, top_k: int, timeout: float) -> dict:
    payload = json.dumps({"text": text, "top_k": top_k}).encode("utf-8")
    req = urllib.request.Request(
        _service_url(), data=payload,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def scan(
    text: str,
    source: str = "normalized",
    *,
    threshold: float = 0.83,
    top_k: int = 5,
    action: Verdict = _DEFAULT_ACTION,
    timeout: float = 2.0,
) -> tuple[list[Hit], str]:
    """对 text 调 VPC-local RAG 检索服务,返回 (hits, status)。

    服务契约(POST RAG_SERVICE_URL):
      请求  {"text": <str>, "top_k": <int>}
      响应  {"max_similarity": <float>, "matches": [{"doc_id","chunk_id","score"}, ...]}

    status:
      - "ok":服务正常返回(无论是否命中)。
      - "unreachable":网络不可达 / 超时 / 坏 JSON / 缺字段 → fail-closed 侧,交引擎标 "L3.7 skipped"。
    命中判据:max_similarity >= threshold(阈值须经标定,见 experiments/rag/threshold_sweep.py)。
    """
    if not text or not text.strip():
        return [], "ok"
    try:
        resp = _call_service(text, top_k, timeout)
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        # 不可达 / 超时 / 坏 JSON(JSONDecodeError ⊂ ValueError)——均记 unreachable,绝不当 PASS
        return [], "unreachable"

    try:
        matches = resp.get("matches") or []
        # max_similarity 优先取服务给的;缺失则从 matches 推。
        max_sim = resp.get("max_similarity")
        if max_sim is None:
            max_sim = max((float(m.get("score", 0.0)) for m in matches), default=0.0)
        max_sim = float(max_sim)
    except (TypeError, ValueError, AttributeError):
        return [], "unreachable"  # 响应结构非法,按不可达处理(fail-closed 侧,不静默放行)

    hits: list[Hit] = []
    if max_sim >= threshold and matches:
        # 取相似度最高的一条作代表(top-1);其余 matches 只影响 max_sim,不逐条产 Hit。
        best = max(matches, key=lambda m: float(m.get("score", 0.0)))
        doc_id = str(best.get("doc_id", "?"))
        chunk_id = str(best.get("chunk_id", "0"))
        score = float(best.get("score", max_sim))
        hits.append(Hit(
            Layer.L37,
            f"rag:{doc_id}#{chunk_id}",
            "PROPRIETARY_SIMILARITY",
            (-1, -1),                              # 语义近邻无字面 span
            f"sim={score:.2f} doc={doc_id}",       # ★ 非原文标签,绝不放 query/语料片段
            action,
            confidence=score,                      # 相似度分入 confidence,供 _dedup 保最高
            source=source,
        ))
    return hits, "ok"
