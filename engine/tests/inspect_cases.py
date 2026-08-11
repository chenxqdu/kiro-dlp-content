#!/usr/bin/env python3
#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
"""逐条三合一检视器（只读）——「输入原文 → 效果(裁决/脱敏) → 延迟」拼在一张卡片里。

现有 runner 各只打印一部分且按 ID 索引：run_offline 有 verdict/总 ms 无输入原文/分层延迟；
run_layers 有分层 ms 无 verdict 值/输入原文；输入原文只存在于 fixture JSON。本脚本把两者 join：
按用例 ID 取 fixture 的输入文本，配一次裁决的效果+分层延迟，逐条渲染。

★ 只读：不改任何生产代码、不写 fixture、不碰引擎内部。全部靠 import 复用两个 runner 的判定件
  （run_offline 的 _IP/Case/evaluate/_l3_absent；run_layers 的 LAYER_FILES/_presidio_up/_check_hits）。

两方案共享同一引擎（engine/dlp），故同一套用例可有两种取数来源：
  · 本地（默认）—— 直接 import 引擎跑 scan()/各层 scan()，覆盖两方案共享内核（方案一/离线）。
  · --via-http <url> —— 把 56 集文本包 CodeWhisperer 信封 POST 到方案二 /inspect 真链路服务，
    解析返回 JSON 拿 verdict/top_layer/rules/latency_ms/redacted_body/forced_block，
    补上方案二 Tier D stdout 缺的逐条延迟。

★ 延迟口径：卡片上的 ms 一律「示意·单次」——
  本地冷跑离线时 L3 会把 Presidio 连接超时计入（非真 NER）；via-http 是真引擎单发耗时。
  基准分位数以 k6 压测为准（方案一 results-2026-08-10/perf/ 03 §9；方案二 03 测试报告 §8）。

★ 不外泄：命中明细只回 layer/rule/entity/field_path/confidence/action，绝不含 matched(原始敏感
  子串)/span —— 与方案二 /inspect 契约一致。REDACT 的脱敏后文本本就安全，照录。

用法：
  cd engine && python3 -m tests.inspect_cases [过滤] [来源] [输出]
过滤（可组合）：
  --id S1-01,L0-POS-01   指定用例（跨两集按 ID 命中）
  --layer L0|L1|L2|L3|L3.5|EGRESS|NORM|L4    只看 78 分层集的某层
  --suite 1..6           只看 56 场景集的某套件
  --set offline|layers|both   选集（默认 both）
  --all                  忽略过滤，全量
来源：
  （默认）本地
  --via-http <inspect-url>    打方案二 /inspect（仅对 56 集有整机 verdict 的用例有意义）
输出：
  --format terminal|md|jsonl  （默认 terminal）
  --report <前缀>        写 <前缀>.md + <前缀>.jsonl（缺省 results-manual/manual_<日期>）
  --full-text            不截断输入/脱敏文本（默认截断 80 字）
  --no-color
  --bedrock              本地模式跑 requires=bedrock 的 L4 向量（⚠ 数据出 VPC，仅功能验证）
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

# 与两个 runner 同款自举：把 engine/ 加入 path，既支持 `-m tests.inspect_cases` 也支持直接跑。
_ENGINE_ROOT = Path(__file__).resolve().parent.parent
if str(_ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_ENGINE_ROOT))

from dlp import (  # noqa: E402
    egress,
    l0_regex,
    l1_secrets,
    l2_entropy,
    l3_presidio,
    l35_glossary,
    l4_semantic,
    normalize,
)
from dlp.engine import DLPEngine, EngineConfig  # noqa: E402

# ★ import 复用（不复制）两个 runner 的判定件
from tests import run_layers as rl  # noqa: E402
from tests import run_offline as ro  # noqa: E402

# CodeWhisperer 请求信封（与 tests/tier_a_smoke.sh 一致）——via-http 包 56 集字符串 content 用
_CW_ENVELOPE_PATH = "conversationState.currentMessage.userInputMessage.content"

_C = {"ok": "\033[32m", "bad": "\033[31m", "skip": "\033[33m",
      "dim": "\033[2m", "hd": "\033[1;36m", "z": "\033[0m"}


def _paint(s: str, key: str, color: bool) -> str:
    return f"{_C[key]}{s}{_C['z']}" if color else s


# ------------------------------------------------------------------ 卡片模型
@dataclass
class Card:
    cid: str
    set_name: str                 # offline | layers
    group: str                    # suite1.. / L0..
    source: str                   # local | via-http <url>
    status: str                   # pass | fail | skip
    kind: str                     # "56" | "78"
    input_text: str = ""
    input_is_json: bool = False
    expected: str = "-"
    actual: str = "-"
    reasons: list = field(default_factory=list)
    hits: list = field(default_factory=list)   # 安全字段 dict（无 matched/span）
    redacted: str | None = None
    forced_block: str | None = None
    latency: dict = field(default_factory=dict)
    latency_src: str = ""         # 延迟来源说明（示意口径）
    l4: str | None = None         # L4 告警类别（78·L4 或 56 套件6）
    notes: list = field(default_factory=list)
    skip_reason: str = ""

    @property
    def mark(self) -> str:
        return {"pass": "✓", "fail": "✗", "skip": "~"}[self.status]


def _safe_hit(h) -> dict:
    """Hit → 安全字段 dict：绝不含 matched/span（与 /inspect 契约对齐）。"""
    return {
        "layer": h.layer.value,
        "rule": h.rule,
        "entity": h.entity,
        "action": h.action.value,
        "source": h.source,
        "field_path": h.field_path,
        "confidence": round(float(h.confidence), 3),
    }


def _fmt_input(x, full: bool) -> tuple[str, bool]:
    is_json = not isinstance(x, str)
    s = json.dumps(x, ensure_ascii=False) if is_json else x
    if not full and len(s) > 80:
        s = s[:80] + "…"
    return s, is_json


def _lat_str(lat: dict) -> str:
    if not lat:
        return "-"
    order = ["L0", "L1", "L2", "L3", "L3.5", "L4", "total", "http_total"]
    keys = [k for k in order if k in lat] + [k for k in lat if k not in order]
    return " ".join(f"{k}={lat[k]:.1f}" if isinstance(lat[k], (int, float)) else f"{k}={lat[k]}"
                     for k in keys)


# ------------------------------------------------------------------ 用例加载
def _load_offline() -> list[dict]:
    out = []
    for s in range(1, 7):
        fp = ro.FIXTURE_DIR / f"suite{s}.json"
        if fp.exists():
            out.extend(json.loads(fp.read_text(encoding="utf-8")))
    return out


def _load_layers() -> list[dict]:
    out = []
    for layer, fn in rl.LAYER_FILES.items():
        fp = rl.FIXTURE_DIR / fn
        if fp.exists():
            for v in json.loads(fp.read_text(encoding="utf-8")):
                v.setdefault("layer", layer)
                out.append(v)
    return out


# ------------------------------------------------------------------ 本地 · 56 集
def _card_offline_local(d: dict, eng: DLPEngine, full: bool) -> Card:
    c = ro.Case(d)
    result = eng.scan(
        c.content, injection_point=c.ip,
        run_async_l4=(c.suite == 6), session_window=c.session_window,
    )
    status, reasons = ro.evaluate(c, result)
    inp, is_json = _fmt_input(c.content, full)
    exp_top = c.expected.get("top_layer")
    act_top = result.top_layer.value if result.top_layer else "-"
    card = Card(
        cid=c.id, set_name="offline", group=f"suite{c.suite}", source="local",
        status=status, kind="56", input_text=inp, input_is_json=is_json,
        expected=f"{c.expected['verdict']}" + (f"/{exp_top}" if exp_top else ""),
        actual=f"{result.verdict.value}/{act_top}",
        reasons=reasons, hits=[_safe_hit(h) for h in result.hits],
        redacted=result.redacted_text, latency=dict(result.latency_ms),
        latency_src="示意·本地单次冷跑（离线 L3 计入 Presidio 连接超时）",
        notes=list(result.notes),
    )
    if c.suite == 6 and result.async_alerts:
        card.l4 = result.async_alerts[0].category
    if status == "skip" and reasons:
        card.skip_reason = reasons[0]
    return card


# ------------------------------------------------------------------ 本地 · 78 集
# 说明：rl.run_vector 只回 (status, reasons, ms)，拿不到 hits/变体供卡片展示；此处按 run_vector
# 同款语义做一次分派，额外捕获 hits/产出，单次扫描不重复跑（L3 只发一次网络）。判定复用 rl._check_hits。
def _card_layer_local(vec: dict, bedrock: bool, presidio: bool, full: bool) -> Card:
    layer = vec["layer"]
    inp_raw = vec.get("text", vec.get("args", vec.get("tool", "")))
    inp, is_json = _fmt_input(inp_raw if layer != "EGRESS"
                              else {"tool": vec.get("tool"), "args": vec.get("args", {})}, full)
    card = Card(cid=vec["id"], set_name="layers", group=layer, source="local",
                status="pass", kind="78", input_text=inp, input_is_json=is_json,
                latency_src="示意·本地单次", notes=[vec.get("note", "")] if vec.get("note") else [])

    req = vec.get("requires")
    if req == "presidio" and not presidio:
        card.status, card.skip_reason = "skip", "需 Presidio（实例上跑）"
        return card
    if req == "bedrock" and not bedrock:
        card.status, card.skip_reason = "skip", "需 --bedrock（数据出 VPC，仅功能验证）"
        return card

    t0 = time.perf_counter()
    hits, reasons = [], []
    if layer in ("L0", "L1", "L2", "L3.5"):
        fn = {"L0": l0_regex.scan, "L1": l1_secrets.scan,
              "L2": l2_entropy.scan, "L3.5": l35_glossary.scan}[layer]
        hits = fn(vec["text"])
        reasons = rl._check_hits(hits, vec)
        card.expected = _fmt_expect_hits(vec)
    elif layer == "L3":
        hits, st = l3_presidio.scan(vec["text"])
        if st == "unreachable":
            card.status, card.skip_reason = "skip", "analyzer unreachable（需 Presidio）"
            return card
        reasons = rl._check_hits(hits, vec)
        if st == "partial":
            reasons.append("L3 partial（部分语言失败）——结果不完整")
        card.expected = _fmt_expect_hits(vec)
    elif layer == "EGRESS":
        hits = egress.scan_channel(vec.get("tool"), vec.get("args", {}))
        reasons = rl._check_hits(hits, vec)
        card.expected = _fmt_expect_hits(vec)
    elif layer == "NORM":
        func = vec.get("func", "expand")
        if func == "expand":
            blobs = normalize.expand(vec["text"], session_window=vec.get("session_window"))
        else:
            r = getattr(normalize, func)(vec["text"])
            blobs = [r if isinstance(r, str) else ""]
        for sub in vec.get("expect_contains", []):
            if not any(sub in (b or "") for b in blobs):
                reasons.append(f"无任何变体含 {sub!r}")
        for sub in vec.get("expect_not_contains", []):
            if any(sub in (b or "") for b in blobs):
                reasons.append(f"存在变体含 {sub!r}（不应出现）")
        card.expected = f"func={func} 含{vec.get('expect_contains', [])}"
        card.actual = "变体: " + " | ".join(b[:40] for b in blobs[:3])
    elif layer == "L4":
        alerts = l4_semantic.analyze(vec["text"], use_bedrock=bool(vec.get("use_bedrock")))
        got = alerts[0].category if alerts else None
        want = vec.get("expect_alert")
        reasons = [] if got == want else [f"告警期望 {want} 实际 {got}"]
        if vec.get("use_bedrock") and alerts and not alerts[0].model.startswith("bedrock:"):
            reasons.append(f"要求 bedrock 后端，实际 {alerts[0].model}（静默回退启发式）")
        card.expected = f"alert={want}"
        card.l4 = got
        card.actual = f"alert={got}"
    else:
        reasons = [f"未知 layer {layer}"]

    card.latency = {layer: (time.perf_counter() - t0) * 1000}
    card.hits = [_safe_hit(h) for h in hits]
    if card.actual == "-" and hits:
        card.actual = "命中: " + ",".join(sorted({h.rule for h in hits}))
    elif card.actual == "-":
        card.actual = "无命中"
    card.reasons = reasons
    card.status = "pass" if not reasons else "fail"
    return card


def _fmt_expect_hits(vec: dict) -> str:
    if vec.get("exact_none"):
        return "零命中"
    mh = vec.get("must_hit", [])
    if mh:
        return "命中 " + ";".join(f"{w.get('rule', '?')}/{w.get('entity', '?')}:{w.get('action', '?')}"
                                  for w in mh)
    return "（见 must_not_hit）"


# ------------------------------------------------------------------ via-http · 56 集
def _health(base: str) -> tuple[bool, str]:
    url = base.rstrip("/") + "/health"
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            body = json.loads(r.read().decode("utf-8"))
            return True, json.dumps(body, ensure_ascii=False)
    except (urllib.error.URLError, OSError, ValueError) as e:
        return False, f"{type(e).__name__}: {e}"


def _wrap_envelope(content):
    """字符串 content 包 CodeWhisperer 信封；dict content（mcp_call）直接作为 body。"""
    if isinstance(content, str):
        return {"conversationState": {"currentMessage": {"userInputMessage": {"content": content}}}}
    return content  # dict：server json.loads 后引擎递归展开字符串叶子


def _inspect(base: str, body_obj) -> tuple[int, dict]:
    url = base.rstrip("/") + "/inspect"
    data = json.dumps(body_obj, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:  # 503/413 等仍是服务的真实应答，读出来展示
        try:
            return e.code, json.loads(e.read().decode("utf-8"))
        except Exception:
            return e.code, {"error": f"http_{e.code}"}


def _remote_hit_matches(rules: list, want: dict) -> bool:
    for h in rules:
        if "entity" in want and h.get("entity") != want["entity"]:
            continue
        if "action" in want and h.get("action") != want["action"]:
            continue
        if "rule" in want and h.get("rule") != want["rule"]:
            continue
        return True
    return False


def _card_offline_via_http(d: dict, base: str, full: bool) -> Card:
    c = ro.Case(d)
    inp, is_json = _fmt_input(c.content, full)
    exp_top = c.expected.get("top_layer")
    card = Card(cid=c.id, set_name="offline", group=f"suite{c.suite}",
                source=f"via-http {base}", status="pass", kind="56",
                input_text=inp, input_is_json=is_json,
                expected=f"{c.expected['verdict']}" + (f"/{exp_top}" if exp_top else ""),
                latency_src="示意·远程单发（方案二真引擎；含 http_total）")
    code, payload = _inspect(base, _wrap_envelope(c.content))
    if code != 200:
        card.status = "fail"
        card.actual = f"HTTP {code}"
        card.reasons = [f"/inspect 非 200：{payload.get('error', payload)}"]
        return card

    rv = str(payload.get("verdict", "")).lower()
    act_top = payload.get("top_layer") or "-"
    card.actual = f"{rv}/{act_top}"
    card.hits = payload.get("rules", [])
    card.latency = dict(payload.get("latency_ms", {}))
    card.forced_block = payload.get("forced_block")
    card.notes = list(payload.get("notes", []))
    if payload.get("redacted_body") is not None:
        rb = payload["redacted_body"]
        card.redacted = rb if full or len(rb) <= 80 else rb[:80] + "…"

    reasons = []
    if rv != c.expected["verdict"]:
        reasons.append(f"verdict 期望 {c.expected['verdict']} 实际 {rv}")
    for want in c.expected.get("must_hit", []):
        if not _remote_hit_matches(card.hits, want):
            reasons.append(f"缺 must_hit {want}")
    # /inspect 固定 PROMPT 注入点：非 prompt 用例的差异属预期，降级为 note 不算硬失败
    if c.ip.value != "prompt":
        card.notes.append(f"⚠ via-http 固定 PROMPT 注入点，本例期望注入点={c.ip.value}，差异属预期")
        if reasons:
            card.status = "skip"
            card.skip_reason = "注入点差异（非 prompt 用例，via-http 不判定）"
            card.reasons = reasons
            return card
    card.reasons = reasons
    card.status = "pass" if not reasons else "fail"
    return card


# ------------------------------------------------------------------ 过滤
def _match_filters(d: dict, set_name: str, args) -> bool:
    if args.ids and d["id"] not in args.ids:
        return False
    if set_name == "offline" and args.suite and d.get("suite") != args.suite:
        return False
    if set_name == "layers" and args.layer and d.get("layer") != args.layer:
        return False
    return True


# ------------------------------------------------------------------ 渲染：终端
def _print_terminal(cards: list[Card], color: bool, full: bool) -> None:
    cur = None
    for c in cards:
        if c.group != cur:
            cur = c.group
            print("\n" + _paint("=" * 96, "hd", color))
            print(_paint(f" {c.set_name.upper()} · {c.group}", "hd", color))
            print(_paint("=" * 96, "hd", color))
        key = {"pass": "ok", "fail": "bad", "skip": "skip"}[c.status]
        head = f"[{c.cid}] {_paint(c.mark, key, color)}  期望={c.expected}  实际={c.actual}  «{c.source}»"
        print("\n" + head)
        print(f"  输入{'(JSON)' if c.input_is_json else ''}: {c.input_text}")
        if c.hits:
            hs = "; ".join(f"{h.get('rule')}·{h.get('entity')}·{h.get('action')}"
                           f"·{h.get('source', '-')}" for h in c.hits)
            print(f"  命中: {hs}")
        if c.redacted is not None:
            print(f"  脱敏后: {_paint(c.redacted, 'ok', color)}")
        if c.forced_block:
            print(f"  {_paint('forced_block=' + c.forced_block, 'bad', color)}")
        if c.l4 is not None:
            print(f"  L4 告警: {c.l4}")
        print(f"  延迟(ms): {_lat_str(c.latency)}   [{c.latency_src}]")
        if c.status == "skip" and c.skip_reason:
            print(f"  {_paint('SKIP: ' + c.skip_reason, 'skip', color)}")
        for r in c.reasons:
            print(f"  {_paint('· ' + r, 'bad' if c.status == 'fail' else 'skip', color)}")
        for n in c.notes:
            if n:
                print(f"  {_paint('note: ' + n, 'dim', color)}")


def _summary(cards: list[Card], color: bool) -> int:
    agg = {"pass": 0, "fail": 0, "skip": 0}
    for c in cards:
        agg[c.status] += 1
    print("\n" + _paint("-" * 96, "hd", color))
    print(f"  合计 {len(cards)} 条：{_paint(str(agg['pass']) + ' pass', 'ok', color)}  "
          f"{_paint(str(agg['fail']) + ' fail', 'bad', color)}  "
          f"{_paint(str(agg['skip']) + ' skip', 'skip', color)}")
    print("  （SKIP 不算 fail；ms 为示意·单次，基准分位以 k6 压测为准）")
    return 1 if agg["fail"] else 0


# ------------------------------------------------------------------ 渲染：报告
_MD_HEAD = ("<!-- Copyright (c) 2026 Amazon.com and Affiliates. -->\n"
            "<!-- SPDX-License-Identifier: CC-BY-4.0 -->\n\n")


def _write_report(cards: list[Card], prefix: Path, argv: str) -> None:
    prefix.parent.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    # ---- markdown ----
    md = [_MD_HEAD, f"# 逐条三合一检视报告\n",
          f"- 生成: {stamp}\n- 命令: `python3 -m tests.inspect_cases {argv}`\n",
          "- 延迟(ms)为**示意·单次**（本地冷跑离线 L3 计入 Presidio 连接超时；"
          "via-http 为真引擎单发）；**基准分位以 k6 压测为准**"
          "（方案一 `results-2026-08-10/perf/` 03 §9；方案二 03 测试报告 §8）。\n",
          "- 命中明细仅含 layer/rule/entity/action/source，**无 matched/span**（与 /inspect 契约一致）。\n"]
    cur = None
    for c in cards:
        if c.group != cur:
            cur = c.group
            md.append(f"\n## {c.set_name.upper()} · {c.group}\n")
            md.append("| ID | ✓ | 期望 | 实际 | 来源 | 延迟(ms) |\n|---|---|---|---|---|---|\n")
        md.append(f"| {c.cid} | {c.mark} | {c.expected} | {c.actual} | "
                  f"{c.source} | {_lat_str(c.latency)} |\n")
    # 明细折叠
    md.append("\n---\n\n## 逐条明细\n")
    for c in cards:
        md.append(f"\n<details><summary><b>{c.cid}</b> {c.mark} "
                  f"（{c.set_name}/{c.group}·{c.source}）</summary>\n\n")
        md.append(f"- 输入{'(JSON)' if c.input_is_json else ''}: `{c.input_text}`\n")
        md.append(f"- 期望: `{c.expected}` → 实际: `{c.actual}`\n")
        if c.hits:
            for h in c.hits:
                md.append(f"  - 命中: {h.get('rule')}·{h.get('entity')}·{h.get('action')}"
                          f"·{h.get('source', '-')}·conf={h.get('confidence', '-')}\n")
        if c.redacted is not None:
            md.append(f"- 脱敏后: `{c.redacted}`\n")
        if c.forced_block:
            md.append(f"- **forced_block**: `{c.forced_block}`\n")
        if c.l4 is not None:
            md.append(f"- L4 告警: `{c.l4}`\n")
        md.append(f"- 延迟(ms): {_lat_str(c.latency)}  _[{c.latency_src}]_\n")
        if c.skip_reason:
            md.append(f"- SKIP: {c.skip_reason}\n")
        for r in c.reasons:
            md.append(f"- ✗ {r}\n")
        for n in c.notes:
            if n:
                md.append(f"- note: {n}\n")
        md.append("\n</details>\n")
    agg = {"pass": 0, "fail": 0, "skip": 0}
    for c in cards:
        agg[c.status] += 1
    md.append(f"\n---\n\n合计 {len(cards)} 条：{agg['pass']} pass / "
              f"{agg['fail']} fail / {agg['skip']} skip（SKIP 不算 fail）。\n")
    md_path = prefix.with_suffix(".md")
    md_path.write_text("".join(md), encoding="utf-8")

    # ---- jsonl（原始记录）----
    jl_path = prefix.with_suffix(".jsonl")
    with jl_path.open("w", encoding="utf-8") as f:
        for c in cards:
            f.write(json.dumps({
                "id": c.cid, "set": c.set_name, "group": c.group, "source": c.source,
                "status": c.status, "input": c.input_text, "input_is_json": c.input_is_json,
                "expected": c.expected, "actual": c.actual, "hits": c.hits,
                "redacted": c.redacted, "forced_block": c.forced_block,
                "latency_ms": c.latency, "l4": c.l4, "notes": c.notes,
                "reasons": c.reasons, "skip_reason": c.skip_reason,
            }, ensure_ascii=False) + "\n")
    print(f"报告已写入:\n  {md_path}\n  {jl_path}")


# ------------------------------------------------------------------ main
def main() -> int:
    ap = argparse.ArgumentParser(description="逐条三合一检视器（只读）")
    ap.add_argument("--id", default=None, help="逗号分隔用例 ID（跨两集）")
    ap.add_argument("--layer", default=None, help="只看 78 集某层 L0/L1/L2/L3/L3.5/EGRESS/NORM/L4")
    ap.add_argument("--suite", type=int, default=None, help="只看 56 集某套件 1-6")
    ap.add_argument("--set", dest="set_", choices=["offline", "layers", "both"], default="both")
    ap.add_argument("--all", action="store_true", help="忽略过滤，全量")
    ap.add_argument("--via-http", dest="via_http", default=None,
                    help="打方案二 /inspect 的 base url（仅 56 集有意义）")
    ap.add_argument("--format", dest="fmt", choices=["terminal", "md", "jsonl"], default="terminal")
    ap.add_argument("--report", default=None, help="报告前缀（缺省 results-manual/manual_<日期>）")
    ap.add_argument("--full-text", dest="full", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--bedrock", action="store_true", help="本地跑 requires=bedrock 的 L4（⚠ 数据出 VPC）")
    args = ap.parse_args()
    args.ids = set(x.strip() for x in args.id.split(",")) if args.id else None
    if args.layer == "L35":
        args.layer = "L3.5"
    if args.all:
        args.ids = args.suite = args.layer = None
    color = not args.no_color

    want_offline = args.set_ in ("offline", "both")
    want_layers = args.set_ in ("layers", "both")

    cards: list[Card] = []

    # ---- 56 集 ----
    if want_offline:
        offline = [d for d in _load_offline() if _match_filters(d, "offline", args)]
        if args.via_http:
            ok, info = _health(args.via_http)
            if not ok:
                print(_paint(f"⚠ /health 不可达（{info}）——方案二服务须在 DLP/proxy 主机经 SSM 跑；"
                             f"整批标 SKIP，不伪造。", "skip", color))
                for d in offline:
                    c = ro.Case(d)
                    inp, is_json = _fmt_input(c.content, args.full)
                    cards.append(Card(cid=c.id, set_name="offline", group=f"suite{c.suite}",
                                      source=f"via-http {args.via_http}", status="skip", kind="56",
                                      input_text=inp, input_is_json=is_json,
                                      expected=c.expected["verdict"],
                                      skip_reason=f"service-down: {info}"))
            else:
                print(_paint(f"✓ /health ok（{info}）", "ok", color))
                for d in offline:
                    cards.append(_card_offline_via_http(d, args.via_http, args.full))
        else:
            eng = DLPEngine(EngineConfig())
            for d in offline:
                cards.append(_card_offline_local(d, eng, args.full))

    # ---- 78 集 ----
    if want_layers:
        layers = [d for d in _load_layers() if _match_filters(d, "layers", args)]
        if args.via_http:
            for d in layers:
                inp, is_json = _fmt_input(d.get("text", d.get("args", d.get("tool", ""))), args.full)
                cards.append(Card(cid=d["id"], set_name="layers", group=d["layer"],
                                  source=f"via-http {args.via_http}", status="skip", kind="78",
                                  input_text=inp, input_is_json=is_json,
                                  skip_reason="not-applicable-to-http（78 分层集不经 /inspect 整机裁决）"))
        else:
            presidio = rl._presidio_up()
            for d in layers:
                cards.append(_card_layer_local(d, args.bedrock, presidio, args.full))

    if not cards:
        print("无匹配用例（检查 --id/--layer/--suite/--set）。")
        return 0

    # ---- 输出 ----
    argv = " ".join(sys.argv[1:])
    if args.fmt == "terminal":
        _print_terminal(cards, color, args.full)
        rc = _summary(cards, color)
        if args.report:
            _write_report(cards, Path(args.report), argv)
        return rc

    # md / jsonl → 落盘（默认 results-manual/manual_<日期>）
    prefix = Path(args.report) if args.report else (
        _ENGINE_ROOT.parent / "results-manual" / f"manual_{time.strftime('%Y%m%d')}")
    _write_report(cards, prefix, argv)
    return _summary(cards, color)


if __name__ == "__main__":
    sys.exit(main())
