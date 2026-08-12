#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
"""
Kiro DLP mitmproxy addon —— 方案二「联动」版

链路：nginx(ssl_preread) 仅把 runtime.<region>.kiro.dev 路由到 127.0.0.1:8443（本 addon
      所在的 mitmdump reverse），其余 SNI 全部 L4 透传、永不解密。本 addon 在请求腿
      解密 GenerateAssistantResponse（AWS event-stream 流式）后，把明文 body POST 给
      【VPC 内网 DLP 判定服务】(/inspect)，按裁决处置：
          BLOCK  -> 合成 AWS 建模异常短路（不转发上游）
          REDACT -> 用脱敏后的完整 JSON 改写请求体，再转发
          PASS   -> 原样转发
      非推理请求（握手/token 刷新/心跳）不调 DLP，直接放行、仅计数。

────────────────────────────────────────────────────────────────────────
关键事实（已核实，勿改）：
  - Kiro 推理面鉴权 = Bearer/OIDC，不是 SigV4 -> 读/改 body、短路都不破坏签名，安全。
  - 请求体是 x-amz-json-1.x；响应是 AWS event-stream（分块流式，必须 stream=True 透传）。
  - DLP 判定全程闭环在 VPC 内（引擎 + Presidio 都在 DLP 主机），请求体绝不发第三方 LLM。
    本 addon 不懂 CodeWhisperer body schema：把整个解密 bytes 交给判定服务，
    由服务独占 json.loads + 引擎 extract 递归展开字符串叶子。

★ 相对最初设计规格做的【加固】（附理由，勿回退）：
  1) 用 stdlib `logging` 而非 `ctx.log` —— mitmproxy ≥v11 已弃用 ctx.log，stdlib logging
     会被 mitmproxy 正确路由，且便于离线单测。
  2) 裁决 gate 只锚定 `X-Amz-Target endswith GenerateAssistantResponse`，不把
     `Host==BUMP_HOST` 作为 skip 条件。理由：nginx map 已物理保证【只有】bump 域能
     到达本 addon（其余走 ssl_preread 透传），因此这里 100% 是 bump 域流量；
     再用 Host 头做 skip 会在 Host 头异常/缺失时【漏审 = fail-open】。Host 头仅记日志。
  3) 传输层不可达/超时（连不上、read timeout）-> 吃 DLP_FAIL_MODE；
     判定服务返回 HTTP 错误码（尤其 503 = 服务自认无法扫描）-> 【恒 fail-closed】，
     无视 DLP_FAIL_MODE。二者严格分流（规格 D4）。
  4) 「内容已存在/已判定却无法安全处置」三类（body 超限 / REDACT 无 body / REDACT body
     非合法 JSON / 未知 verdict）恒 fail-closed，即使 DLP_FAIL_MODE=open（规格 D3）。

配置（systemd Environment= 注入）：
  - DLP_INSPECT_URL    判定服务地址，无默认值 —— 缺失即拒启（规格 D5，防误指旧址静默放行）
  - MITM_BUMP_DOMAIN   被 bump 的域名，无默认值 —— 缺失即拒启；用于上游自环自检
  - DLP_FAIL_MODE      closed（默认，安全）| open（灰度，务必告警）
  - DLP_TIMEOUT        判定调用总超时秒，默认 8.0（按 Presidio p99 标定，见残留风险）
  - DLP_MAX_BODY_BYTES 明文 body 上限，超过恒 fail-closed，默认 8 MiB；0=不限
"""

import asyncio
import ipaddress
import json
import logging
import os
import socket

from mitmproxy import http

logger = logging.getLogger("kiro_dlp")

INFER_OP = "GenerateAssistantResponse"

# httpx 优先（连接池 + connect/read 分离超时）；venv 无则回落 asyncio.to_thread + urllib，
# 二者都不阻塞单线程 asyncio 事件循环（规格 D1）。
try:
    import httpx

    _HAVE_HTTPX = True
except Exception:  # pragma: no cover
    import urllib.error
    import urllib.request

    _HAVE_HTTPX = False


def _env_required(name: str) -> str:
    v = os.environ.get(name, "").strip()
    if not v:
        raise RuntimeError(f"缺少必需环境变量 {name}（拒绝以不安全的默认值启动）")
    return v


def _env(name: str, default: str) -> str:
    v = os.environ.get(name, "").strip()
    return v if v else default


class _Unreachable(Exception):
    """传输层不可达/超时（连不上判定服务）—— 吃 DLP_FAIL_MODE。"""


def _local_ips() -> set:
    ips = set()
    try:
        ips.add(socket.gethostbyname(socket.gethostname()))
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("169.254.169.254", 80))  # link-local；UDP connect 不实际发包
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return ips


def _assert_upstream_not_self(host: str) -> None:
    """规格 D7：bump 域绝不能解析到本机/loopback，否则 nginx->mitm->上游解析回 nginx 死环。"""
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except Exception as e:
        # 解析失败：不硬阻断（真正连接上游时会大声失败），仅告警。
        logger.warning("[DLP] 上游 %s 解析失败(启动继续，连接时会暴露): %s", host, e)
        return
    resolved = {ai[4][0] for ai in infos}
    locals_ = _local_ips()
    for ip in resolved:
        try:
            is_lo = ipaddress.ip_address(ip).is_loopback
        except ValueError:
            is_lo = False
        if is_lo or ip in locals_:
            raise RuntimeError(
                f"上游 {host} 解析到本机地址 {ip} —— 会形成 nginx->mitm->nginx 自环，"
                f"拒绝启动。请清理 EC2 /etc/hosts（本机绝不写 kiro 域名）。"
            )
    logger.info("[DLP] 上游 %s 解析自检 OK resolved=%s local=%s",
                host, sorted(resolved), sorted(locals_))


class KiroDLP:
    def __init__(self) -> None:
        self.url = _env_required("DLP_INSPECT_URL")
        self.bump_host = _env_required("MITM_BUMP_DOMAIN")
        self.fail_open = _env("DLP_FAIL_MODE", "closed").lower() == "open"
        try:
            self.timeout = float(_env("DLP_TIMEOUT", "8.0"))
        except ValueError:
            self.timeout = 8.0
        try:
            self.max_body = int(_env("DLP_MAX_BODY_BYTES", str(8 * 1024 * 1024)))
        except ValueError:
            self.max_body = 8 * 1024 * 1024

        self._client = None  # httpx.AsyncClient，延迟到事件循环内建
        self.n_infer = self.n_other = 0
        self.n_pass = self.n_redact = self.n_block = self.n_failclosed = 0

    # ---------------- 生命周期 ----------------
    def running(self) -> None:
        _assert_upstream_not_self(self.bump_host)  # 自环自检，命中则抛异常拒启
        logger.info(
            "[DLP] addon started url=%s bump=%s fail=%s timeout=%.1fs max_body=%d backend=%s",
            self.url, self.bump_host, "open" if self.fail_open else "closed",
            self.timeout, self.max_body, "httpx" if _HAVE_HTTPX else "urllib+thread",
        )
        if self.fail_open:
            logger.warning(
                "[DLP] FAIL-OPEN（灰度）：判定服务不可达时将【放行未审查流量】。生产必须 DLP_FAIL_MODE=closed。"
            )

    async def done(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                pass

    # ---------------- 请求钩子（async，绝不阻塞事件循环）----------------
    async def request(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        target = req.headers.get("X-Amz-Target", "")

        # 非推理请求：nginx 已保证此处 100% 是 bump 域，X-Amz-Target 用于区分推理 vs 握手/心跳。
        if not target.endswith(INFER_OP):
            self.n_other += 1
            if self.n_other % 200 == 0:
                logger.info("[DLP] passthrough(non-infer) count=%d host=%s path=%s",
                            self.n_other, req.host_header, req.path)
            return

        self.n_infer += 1

        try:
            body = req.get_content()  # 解密 + 按 Content-Encoding 解压后的 bytes
        except Exception as e:
            # body 解码失败：内容不可读也不可判 -> 恒 fail-closed（不静默放行未审查内容）。
            logger.warning("[DLP] get_content 解码失败: %s -> fail-closed", e)
            return self._fail_closed(flow, "body_decode_error")

        if not body:
            # 空 body：结构性无害，放行 + 告警（无内容可外泄）。
            logger.warning("[DLP] 空 body 放行 path=%s", req.path)
            return

        if self.max_body and len(body) > self.max_body:
            logger.warning("[DLP] body 超限 %d>%d -> fail-closed", len(body), self.max_body)
            return self._fail_closed(flow, "body_too_large")  # 内容已存在，恒 closed

        # 调判定服务。异常分流：传输不可达 -> fail 策略；其它（含 503/JSON 错）-> 恒 closed。
        try:
            verdict = await self._inspect(body)
        except _Unreachable as e:
            logger.warning("[DLP] 判定服务不可达 fail-%s: %s",
                           "open" if self.fail_open else "closed", e)
            if self.fail_open:
                return  # 灰度放行（已告警）
            return self._fail_closed(flow, "dlp_unreachable")
        except Exception as e:
            # 服务返 HTTP 错误码 / 响应非 JSON / 其它未预期 -> 恒 fail-closed（规格 D3/D4）。
            logger.warning("[DLP] 判定异常 -> fail-closed: %s: %s", type(e).__name__, e)
            return self._fail_closed(flow, "dlp_error")

        decision = str(verdict.get("verdict", "")).upper()

        if decision == "PASS":
            self.n_pass += 1
            if self.n_pass % 100 == 0:
                logger.info("[DLP] PASS count=%d", self.n_pass)
            return

        if decision == "BLOCK":
            self.n_block += 1
            logger.warning("[DLP] KIRO-BLOCK top=%s rules=%s notes=%s",
                           verdict.get("top_layer"), verdict.get("rules"), verdict.get("notes"))
            flow.response = self._block_response(req, verdict)
            flow.metadata["kiro_dlp_synthetic"] = True
            return

        if decision == "REDACT":
            rb = verdict.get("redacted_body")
            if not isinstance(rb, str) or not rb:
                logger.error("[DLP] REDACT 缺 redacted_body -> fail-closed")
                return self._fail_closed(flow, "redact_without_body")  # 恒 closed
            try:
                json.loads(rb)  # 规格 D6：必须是完整合法 JSON 信封，否则上游 400
            except Exception:
                logger.error("[DLP] REDACT redacted_body 非合法 JSON -> fail-closed")
                return self._fail_closed(flow, "redact_bad_json")  # 恒 closed
            # 规格 D6：改写后载荷摘要头会失配 -> 删除（Bearer 鉴权不依赖它，删除安全）。
            for h in ("content-md5", "x-amz-content-sha256"):
                if h in req.headers:
                    del req.headers[h]
            req.set_content(rb.encode("utf-8"))  # 自动修正 Content-Length
            self.n_redact += 1
            logger.warning("[DLP] KIRO-REDACT top=%s rules=%s",
                           verdict.get("top_layer"), verdict.get("rules"))
            return

        # 未知 verdict：判定服务返回预期外值 -> 恒 fail-closed（不静默放行）。
        logger.error("[DLP] 未知 verdict=%r -> fail-closed", verdict.get("verdict"))
        return self._fail_closed(flow, "unknown_verdict")

    # ---------------- 响应钩子：event-stream 必须流式透传 ----------------
    def responseheaders(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        if flow.metadata.get("kiro_dlp_synthetic"):
            return  # 我们自己合成的小响应（BLOCK/fail-closed）不走上游流式
        flow.response.stream = True  # 上游 event-stream 不缓冲，否则 IDE/TUI 卡死

    # ---------------- 判定调用（不阻塞事件循环）----------------
    async def _inspect(self, body: bytes) -> dict:
        headers = {"Content-Type": "application/json"}
        if _HAVE_HTTPX:
            if self._client is None:
                # 单线程 asyncio：is None 判断与赋值间无 await，不会并发重复建池。
                self._client = httpx.AsyncClient(
                    timeout=httpx.Timeout(self.timeout, connect=min(2.0, self.timeout)),
                    limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
                )
            try:
                resp = await self._client.post(self.url, content=body, headers=headers)
            except (httpx.TimeoutException, httpx.TransportError) as e:
                raise _Unreachable(str(e)) from e
            resp.raise_for_status()  # 503/4xx -> HTTPStatusError -> 上层恒 fail-closed
            return resp.json()

        # 回落：标准库 urllib 丢线程池，await 不占事件循环。
        return await asyncio.to_thread(self._inspect_urllib, body, headers)

    def _inspect_urllib(self, body: bytes, headers: dict) -> dict:
        req = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError:
            raise  # 服务端 HTTP 错误码（如 503）-> 上层恒 fail-closed
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            raise _Unreachable(str(e)) from e  # 传输不可达 -> 上层吃 fail 策略
        return json.loads(raw.decode("utf-8"))

    # ---------------- fail-closed / 响应构造（严禁 raise，规格 D2）----------------
    def _fail_closed(self, flow: http.HTTPFlow, reason: str) -> None:
        self.n_failclosed += 1
        flow.response = self._service_unavailable(flow.request, reason)
        flow.metadata["kiro_dlp_synthetic"] = True
        logger.warning("[DLP] KIRO-FAILCLOSED reason=%s", reason)

    @staticmethod
    def _amz_ct(req: http.Request) -> str:
        ct = req.headers.get("Content-Type", "")
        return ct if ct.startswith("application/x-amz-json") else "application/x-amz-json-1.1"

    def _block_response(self, req: http.Request, verdict: dict) -> http.Response:
        # 规格 D11：AWS 建模异常框架。HTTP 400（4xx 明确非重试），__type + message。
        etype = "CorpDLPBlockedException"
        body = json.dumps({
            "__type": etype,
            "message": verdict.get("message") or "blocked_by_corp_dlp",
            "top_layer": verdict.get("top_layer"),
            "rules": verdict.get("rules"),
        }, ensure_ascii=False).encode("utf-8")
        return http.Response.make(400, body, {
            "Content-Type": self._amz_ct(req),
            "x-amzn-ErrorType": etype,
            "Cache-Control": "no-store",
        })

    def _service_unavailable(self, req: http.Request, reason: str) -> http.Response:
        etype = "ServiceUnavailableException"
        body = json.dumps({
            "__type": etype,
            "message": f"dlp_fail_closed:{reason}",
        }, ensure_ascii=False).encode("utf-8")
        return http.Response.make(503, body, {
            "Content-Type": self._amz_ct(req),
            "x-amzn-ErrorType": etype,
            "Retry-After": "5",
            "Cache-Control": "no-store",
        })


addons = [KiroDLP()]
