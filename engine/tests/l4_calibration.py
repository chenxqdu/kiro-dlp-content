#!/usr/bin/env python3
"""阶段4 —— L4 Bedrock 异步告警标定(03 文档 §6 阶段4)。

对套件6 逐条:
1. 同步链路断言:engine.scan(use_bedrock_l4=True, run_async_l4=True) 的 verdict
   必须仍为 pass(L4 永不写 verdict —— 硬约束回归)。
2. L4 双模型标定:Qwen3-32B(main)与 Llama-3.1-8B(control)各自直接调
   l4_semantic.analyze(use_bedrock=True),记录 告警类别/置信度/延迟,与
   expected.async_l4_category 对账(None = 不得告警)。

⚠ 红线标注:本标定经 Bedrock(us-west-2)= 数据出 VPC,**仅功能验证,非生产配置**;
生产 L4 须自托管/VPC-only(g6 vLLM)。
输出矩阵不手写数字。退出码:同步 verdict 被 L4 污染 → 1;类别不齐仅记录(标定
本身就是测模型能力,不设硬门)。
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

_ENGINE_ROOT = Path(__file__).resolve().parent.parent
if str(_ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_ENGINE_ROOT))

from dlp import l4_semantic  # noqa: E402
from dlp.engine import DLPEngine, EngineConfig  # noqa: E402
from dlp.types import InjectionPoint  # noqa: E402

FIXTURES = _ENGINE_ROOT / "tests" / "fixtures" / "suite6.json"


def main() -> int:
    cases = json.loads(FIXTURES.read_text(encoding="utf-8"))
    eng = DLPEngine(EngineConfig(use_bedrock_l4=True))

    sync_violations = 0
    rows = []
    for c in cases:
        exp_cat = c["expected"].get("async_l4_category")

        # 1) 同步链路:L4 开启也绝不改 verdict
        r = eng.scan(c["content"], injection_point=InjectionPoint.PROMPT,
                     run_async_l4=True)
        if r.verdict.value != c["expected"]["verdict"]:
            sync_violations += 1
            print(f"✗ {c['id']} 同步 verdict 被污染: 期望 "
                  f"{c['expected']['verdict']} 实际 {r.verdict.value}")

        # 2) 双模型标定
        per_model = {}
        for mk in ("main", "control"):
            t0 = time.perf_counter()
            alerts = l4_semantic.analyze(c["content"], use_bedrock=True, model_key=mk)
            ms = (time.perf_counter() - t0) * 1000
            a = alerts[0] if alerts else None
            # 区分"Bedrock 真回了 none"与"调用失败静默回退启发式"
            via_bedrock = bool(a and a.model.startswith("bedrock:"))
            per_model[mk] = {
                "category": a.category if a else None,
                "conf": round(a.confidence, 2) if a else None,
                "ms": round(ms, 1),
                "backend": (a.model if a else "no-alert"),
                "via_bedrock": via_bedrock,
            }
        rows.append((c["id"], exp_cat, per_model))

    print("=" * 110)
    print(f"{'ID':<8}{'期望类别':<24}{'模型':<9}{'实际类别':<30}{'conf':<7}{'ms':>9}  后端")
    print("-" * 110)
    agree = 0
    for cid, exp_cat, pm in rows:
        for mk in ("main", "control"):
            m = pm[mk]
            got = m["category"]
            ok = (got == exp_cat) or (exp_cat is None and got is None)
            mark = "✓" if ok else "≈" if (exp_cat and got) else "✗"
            print(f"{cid:<8}{str(exp_cat):<24}{mk:<9}{str(got):<30}"
                  f"{str(m['conf']):<7}{m['ms']:>9}  {mark} {m['backend'][:46]}")
        if pm["main"]["category"] == pm["control"]["category"]:
            agree += 1
    print("=" * 110)
    exact_main = sum(1 for _, e, pm in rows
                     if pm["main"]["category"] == e)
    exact_ctrl = sum(1 for _, e, pm in rows
                     if pm["control"]["category"] == e)
    print(f"类别精确对齐: main={exact_main}/{len(rows)}  control={exact_ctrl}/{len(rows)}"
          f"  主/对照一致={agree}/{len(rows)}")
    print(f"同步 verdict 污染: {sync_violations}(须 0)")
    print("⚠ 本标定经 Bedrock us-west-2,数据出 VPC —— 仅功能验证,非生产配置。")
    return 1 if sync_violations else 0


if __name__ == "__main__":
    sys.exit(main())
