#!/usr/bin/env python3
#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
"""阶段2 网关集成测(03 文档 §6):经 LiteLLM :4000 验证两个 hook + flowback。

用法(在 kiro-dlp 上、或经 SSH 隧道本机跑):
  python3 test_gateway.py --base-url http://localhost:4000 --key $LITELLM_MASTER_KEY \
      --fixtures ../engine/tests/fixtures --model llama-3.1-8b

- prompt/flowback 类 fixture → POST /chat/completions(flowback 构造 tool role 消息)。
- mcp 类 fixture → 经 apply_guardrail 语义:此处直接调 /chat/completions 把 MCP JSON
  作为 prompt 是不对的;正确路径是 MCP 网关。为在阶段2 可控验证,mcp 类经
  «直连引擎容器»(scan_mcp_call)验证 field_path,经网关验证只覆盖 prompt/flowback。
- 期望:block → HTTP 400 且 detail.error=blocked_by_corp_dlp;
        redact → 200 且上游收到的 prompt 已脱敏(用 echo 模型不可行,改验响应正常 +
                 网关指标文件 verdict=redact);
        pass  → 200。
输出矩阵 + 汇总,不手写数字。
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def call_gateway(base_url: str, key: str, model: str, messages: list, timeout=60,
                 tools: list | None = None):
    body = {"model": model, "messages": messages, "max_tokens": 32}
    if tools:
        body["tools"] = tools
    payload = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{base_url}/chat/completions", data=payload, method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
    )
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode())
            return resp.status, body, (time.perf_counter() - t0) * 1000
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode())
        except Exception:
            body = {}
        return e.code, body, (time.perf_counter() - t0) * 1000


# flowback 序列里 assistant.tool_calls 引用的工具:Bedrock Converse 要求请求同时带
# tools= 定义,否则 LiteLLM 直接 UnsupportedParamsError 400(与 DLP 无关,实测踩坑)。
_FLOWBACK_TOOLS = [{
    "type": "function",
    "function": {
        "name": "read_file",
        "description": "读取本地文件内容",
        "parameters": {"type": "object",
                       "properties": {"path": {"type": "string"}},
                       "required": ["path"]},
    },
}]


def build_messages(case: dict) -> tuple[list, list | None]:
    """返回 (messages, tools)。
    prompt → user 消息(session_window 条目作为前置消息,复现同请求滑窗拼接);
    flowback → 合法 tool-use 序列:assistant.tool_calls → tool 返回值 → user 追问,
    并带 tools 定义(缺任一都会被 LiteLLM/Bedrock 按非法请求 400,与 DLP 无关——
    S5-03/S5-07 前两轮实测分别栽在缺 tool_calls、缺 tools=)。"""
    content = case["content"]
    if case.get("injection_point") == "flowback":
        # tool 返回值须是最后一条:Bedrock(llama Converse)不允许 tool result 与
        # user content 同轮("cannot be provided in the same turn",实测 400)。
        # 模型直接基于工具结果续答,亦更贴近真实回流。
        return [
            {"role": "user", "content": "请读取该文件并总结要点"},
            {"role": "assistant", "content": None, "tool_calls": [{
                "id": "call_test_1", "type": "function",
                "function": {"name": "read_file",
                             "arguments": "{\"path\": \"/tmp/notes.txt\"}"},
            }]},
            {"role": "tool", "tool_call_id": "call_test_1", "content": content},
        ], _FLOWBACK_TOOLS
    msgs = [{"role": "user", "content": w} for w in (case.get("session_window") or [])]
    msgs.append({"role": "user", "content": content})
    return msgs, None


def is_blocked(status: int, body: dict) -> bool:
    if status == 200:
        return False
    s = json.dumps(body, ensure_ascii=False)
    return "blocked_by_corp_dlp" in s


# fail-closed(规格 D4)下,网关会把「脱敏落空」的 redact 强制升级为 400 BLOCK。
# 这些 forced_block 原因是 redact 期望向量在网关侧的**预期收紧**(offline 仍判 redact,
# 见 run_offline.py 只读 verdict),不算失败。l3_unavailable 不在此列——健康 Presidio
# 下不应出现,若出现说明本轮 Presidio 异常,应作为异常暴露而非吞掉。
_REDACT_FAILCLOSED_REASONS = ("redaction_ineffective", "redact_writeback_failed")


def forced_reason(body: dict) -> str:
    """从(可能被 LiteLLM 包装嵌套的)响应体里取 forced_block 原因,取不到返回空串。"""
    s = json.dumps(body, ensure_ascii=False)
    for r in ("redaction_ineffective", "redact_writeback_failed", "l3_unavailable"):
        if r in s:
            return r
    return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://localhost:4000")
    ap.add_argument("--key", required=True)
    ap.add_argument("--fixtures", default="../engine/tests/fixtures")
    ap.add_argument("--model", default="llama-3.1-8b")
    ap.add_argument("--suites", default="1,2,3,5", help="经网关跑的套件(mcp 类跳过)")
    args = ap.parse_args()

    fdir = Path(args.fixtures)
    suites = [int(s) for s in args.suites.split(",")]
    rows, agg = [], {"pass": 0, "fail": 0, "skip": 0}

    for s in suites:
        fp = fdir / f"suite{s}.json"
        if not fp.exists():
            print(f"⚠ 缺 {fp.name}", file=sys.stderr)
            continue
        for case in json.loads(fp.read_text(encoding="utf-8")):
            ip = case.get("injection_point", "prompt")
            if ip in ("mcp", "egress"):
                rows.append((case["id"], s, "SKIP(mcp→直连引擎验证)", "-", "~", 0.0))
                agg["skip"] += 1
                continue
            exp = case["expected"]["verdict"]
            messages, tools = build_messages(case)
            status, body, ms = call_gateway(
                args.base_url, args.key, args.model, messages, tools=tools)
            blocked = is_blocked(status, body)
            reason = forced_reason(body) if blocked else ""
            note = ""
            if exp == "block":
                ok = blocked
            elif exp == "pass":
                ok = (status == 200)
            elif exp == "redact":
                # 正常脱敏 → 200(确已脱敏由网关指标 jsonl 复核);
                # fail-closed 收紧:脱敏落空/无法写回 → 400 forced_block(D4 预期,非失败)。
                if status == 200:
                    ok = True
                elif blocked and reason in _REDACT_FAILCLOSED_REASONS:
                    ok = True
                    note = f"→fail-closed({reason})"
                else:
                    ok = False
            else:
                ok = False
            st = "pass" if ok else "fail"
            agg[st] += 1
            http = f"{status}{'/blocked' if blocked else ''}{note}"
            rows.append((case["id"], s, exp, http, "✓" if ok else "✗", ms))

    print("=" * 104)
    print(f"{'ID':<10}{'套件':<4}{'期望':<26}{'HTTP':<44}{'✓':<3}{'RTT ms':>9}")
    print("-" * 104)
    for cid, s, exp, http, mark, ms in rows:
        print(f"{cid:<10}{s:<4}{exp:<26}{http:<44}{mark:<3}{ms:>9.1f}")
    print("=" * 104)
    print(f"经网关: pass={agg['pass']} fail={agg['fail']} skip(mcp)={agg['skip']}")
    sys.exit(0 if agg["fail"] == 0 else 1)


if __name__ == "__main__":
    main()
