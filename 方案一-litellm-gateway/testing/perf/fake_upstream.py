#!/usr/bin/env python3
"""
假上游(§9.3 法1)—— OpenAI /chat/completions 兼容的 echo 端点。

目的:把上游 LLM 的生成延迟从性能测量里剔除,只留【网关 + DLP 引擎】的净开销。
      与 LiteLLM 的 mock_response 不同(其 usage 硬编码 10/20/30、且不真正走
      转发改写路径),本服务是真实的 HTTP 上游 —— LiteLLM 会把【经 guardrail
      脱敏改写后的 messages】真正 POST 过来,故 REDACT 路径被完整执行。

★ 关键设计:把收到的 messages 内容【回显】进 assistant content。
  这样 k6 客户端能直接检查:
    - PASS   → 响应 echo 里应含原文
    - REDACT → 响应 echo 里应是 [REDACTED:...],【原始 PII 明文必须消失】——
               这正是 §9.6 源1 对 REDACT 的权威判据(脱敏是否真生效、
               明文有没有被挡在网关内没发到上游)
    - BLOCK  → 根本不会打到本服务(400 在网关内短路)

纯 stdlib,零依赖;跑在 kiro-dlp 实例上(python3 自带)。内容不出 VPC。
usage 用真实字符估算(≈len/4),不硬编码,避免 mock_response 的 TPM 压平坑。
"""
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0

import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("FAKE_UPSTREAM_PORT", "18080"))
BIND = os.environ.get("FAKE_UPSTREAM_BIND", "127.0.0.1")
MAX_BODY = 32 * 1024 * 1024


def _extract_text(payload: dict) -> str:
    """拼接所有 messages 的文本 content(含多模态 text 段)。"""
    out = []
    for m in payload.get("messages") or []:
        c = m.get("content")
        if isinstance(c, str):
            out.append(c)
        elif isinstance(c, list):
            for seg in c:
                if isinstance(seg, dict) and isinstance(seg.get("text"), str):
                    out.append(seg["text"])
        # tool_calls 里的 arguments 也回显(flowback/MCP 路径可校验)
        for tc in m.get("tool_calls") or []:
            fn = (tc or {}).get("function") or {}
            if isinstance(fn.get("arguments"), str):
                out.append(fn["arguments"])
    return "\n".join(out)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code: int, obj: dict) -> None:
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
        if self.path.split("?")[0] in ("/health", "/"):
            return self._send(200, {"status": "ok", "role": "fake-upstream"})
        return self._send(404, {"error": "not_found"})

    def do_POST(self):  # noqa: N802
        # 任意 chat/completions 路径都当推理请求(/v1/chat/completions 或 /chat/completions)
        if not self.path.split("?")[0].endswith("/chat/completions"):
            return self._send(404, {"error": "not_found"})
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError):
            return self._send(400, {"error": "bad_content_length"})
        if n <= 0 or n > MAX_BODY:
            return self._send(413, {"error": "body_too_large_or_empty"})
        raw = self.rfile.read(n)
        try:
            payload = json.loads(raw)
        except Exception:
            payload = {}
        echo = _extract_text(payload)
        # 回显收到的(可能已脱敏的)输入;截断防超大响应影响计时
        content = "ECHO:" + (echo[:8000])
        p_tok = max(1, len(echo) // 4)
        c_tok = max(1, len(content) // 4)
        resp = {
            "id": "chatcmpl-fake-upstream",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": payload.get("model", "echo"),
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }],
            "usage": {
                "prompt_tokens": p_tok,
                "completion_tokens": c_tok,
                "total_tokens": p_tok + c_tok,
            },
        }
        return self._send(200, resp)

    def log_message(self, *args):  # 静音访问日志(避免把 echo 内容写进日志)
        pass


def main():
    srv = ThreadingHTTPServer((BIND, PORT), Handler)
    srv.daemon_threads = True
    print(f"fake-upstream listening {BIND}:{PORT} (OpenAI /chat/completions echo)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
