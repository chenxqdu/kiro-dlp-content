#!/usr/bin/env bash
#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
#############################################
# §5 Fail 模式验证（在验证节点 EC2 执行；全程走 9443 临时实例，绝不碰生产 443/8443）
#
# 验证 addon 在【DLP 判定服务异常】时的安全语义（规格 D3/D4）：
#
#   子测 1  hard-down + fail-closed(默认) : DLP 连不上 -> client 503 + 上游零命中（拒未审查流量出网）
#   子测 2  hard-down + fail-open (灰度)  : 同样连不上，但 DLP_FAIL_MODE=open -> 放行(200 + 上游命中)
#   子测 3  slow(>timeout) + fail-closed  : DLP 慢于 DLP_TIMEOUT -> 超时=不可达 -> 503
#   子测 4  DLP 返回 HTTP 503 + fail-OPEN : 服务自认无法扫描 -> 【恒 fail-closed】503，无视 open（D4）
#
# 关键：addon 把「传输不可达」与「HTTP 错误码」严格分流：
#   不可达 -> 吃 DLP_FAIL_MODE；HTTP 503/4xx -> 恒 closed。子测 4 专验后者。
#############################################
set -uo pipefail
CERTS=/etc/mitm/certs
BUMP=runtime.us-east-1.kiro.dev
MITM_PORT=9443
FAKE_DLP_PORT=19000
ECHO_PORT=18080
WORK=/tmp/tierfail
PATHQ="/generateAssistantResponse"
sudo rm -rf "$WORK"; mkdir -p "$WORK"
UP_BODY="$WORK/upstream_body.bin"

BODY='{"conversationState":{"currentMessage":{"userInputMessage":{"content":"普通问题：解释一下二分查找"}}}}'
echo "$BODY" > "$WORK/body.json"

# ---- echo 上游（记录是否被命中）----
cat > "$WORK/echo.py" <<PY
import http.server, socketserver
UP="$UP_BODY"
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_POST(self):
        n=int(self.headers.get("Content-Length",0)); b=self.rfile.read(n) if n else b""
        open(UP,"wb").write(b)
        self.send_response(200); self.send_header("Content-Length","2"); self.end_headers(); self.wfile.write(b"ok")
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Length","2"); self.end_headers(); self.wfile.write(b"ok")
socketserver.TCPServer(("127.0.0.1",$ECHO_PORT),H).serve_forever()
PY
python3 "$WORK/echo.py" >/dev/null 2>&1 &
ECHO_PID=$!

# ---- 可控故障 DLP：模式由 /tmp/tierfail/mode 文件控制（slow|http503）----
cat > "$WORK/fakedlp.py" <<PY
import http.server, time, os
# ★ ThreadingHTTPServer：每请求独立线程。否则 slow 模式的 30s sleep 会阻塞单线程 server，
#   让后续子测的请求在 TCP 队列里干等 -> addon 误判为超时/不可达（测试假象）。
MODEF="$WORK/mode"
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Length","2"); self.end_headers(); self.wfile.write(b"ok")
    def do_POST(self):
        n=int(self.headers.get("Content-Length",0)); self.rfile.read(n) if n else b""
        mode = open(MODEF).read().strip() if os.path.exists(MODEF) else "slow"
        if mode=="slow":
            time.sleep(30)   # 远超 addon DLP_TIMEOUT -> 触发 read 超时
            self.send_response(200); self.send_header("Content-Length","2"); self.end_headers(); self.wfile.write(b"{}")
        elif mode=="http503":
            self.send_response(503); self.send_header("Content-Length","2"); self.end_headers(); self.wfile.write(b"{}")
        else:
            self.send_response(200); self.send_header("Content-Length","2"); self.end_headers(); self.wfile.write(b"{}")
http.server.ThreadingHTTPServer(("127.0.0.1",$FAKE_DLP_PORT),H).serve_forever()
PY

# ---- 启动一个临时 mitmdump（指定 DLP url / fail 模式 / 超时）----
start_mitm () {
  local dlp_url="$1" fail_mode="$2" timeout="$3"
  sudo env HOME=/etc/mitm PYTHONUNBUFFERED=1 \
    DLP_INSPECT_URL="$dlp_url" MITM_BUMP_DOMAIN="$BUMP" \
    DLP_FAIL_MODE="$fail_mode" DLP_TIMEOUT="$timeout" \
    /opt/mitm-venv/bin/mitmdump --mode reverse:http://127.0.0.1:${ECHO_PORT}@127.0.0.1:${MITM_PORT} \
    --set keep_host_header=true --set upstream_cert=false --set connection_strategy=lazy \
    --set confdir=$CERTS -s /etc/mitm/kiro_addon.py >"$WORK/mitm.log" 2>&1 &
  echo $!
}
stop_mitm () { sudo kill "$1" 2>/dev/null; sleep 1; }

fire () {  # $1 label
  sudo rm -f "$UP_BODY"
  local code
  code=$(curl -s -o "$WORK/resp_$1.bin" -w '%{http_code}' \
    --cacert $CERTS/root.crt --resolve ${BUMP}:${MITM_PORT}:127.0.0.1 \
    -X POST "https://${BUMP}:${MITM_PORT}${PATHQ}" \
    -H "Content-Type: application/x-amz-json-1.1" -H "Authorization: Bearer FAKE" \
    -H "X-Amz-Target: Svc.GenerateAssistantResponse" \
    --data-binary @"$WORK/body.json" -m 20)
  local hit; [[ -f "$UP_BODY" ]] && hit=yes || hit=no
  echo "  client_code=$code  upstream_hit=$hit"
  echo "  resp: $(sudo head -c 200 "$WORK/resp_$1.bin" 2>/dev/null)"
}

echo "############### 子测 1: hard-down + fail-CLOSED (默认) ###############"
# DLP 指向一个【无人监听】的端口 -> connect refused = 传输不可达
MP=$(start_mitm "http://127.0.0.1:19999/inspect" "closed" "5.0"); sleep 4
fire s1
echo "  期望: code=503 (ServiceUnavailableException) + upstream_hit=no"
stop_mitm "$MP"

echo
echo "############### 子测 2: hard-down + fail-OPEN (灰度) ###############"
MP=$(start_mitm "http://127.0.0.1:19999/inspect" "open" "5.0"); sleep 4
fire s2
echo "  期望: code=200 + upstream_hit=yes（灰度放行未审查；生产禁用）"
stop_mitm "$MP"

echo
echo "############### 子测 3: slow(>timeout) + fail-CLOSED ###############"
echo "slow" > "$WORK/mode"
python3 "$WORK/fakedlp.py" >/dev/null 2>&1 &
FDLP_PID=$!; sleep 1
MP=$(start_mitm "http://127.0.0.1:${FAKE_DLP_PORT}/inspect" "closed" "3.0"); sleep 4
echo "  (DLP 睡 30s，addon 超时 3s -> read timeout=不可达 -> fail-closed)"
fire s3
echo "  期望: code=503 + upstream_hit=no"
stop_mitm "$MP"

echo
echo "############### 子测 4: DLP 返回 HTTP 503 + fail-OPEN -> 恒 CLOSED (D4) ###############"
# 彻底杀掉子测3的 fake DLP（清除任何 slow 残留连接），另起全新进程只吐 503。
kill "$FDLP_PID" 2>/dev/null; sleep 2
echo "http503" > "$WORK/mode"
python3 "$WORK/fakedlp.py" >/dev/null 2>&1 &
FDLP_PID=$!; sleep 1
# 先独立确认 fake DLP 现在确实返回 503（排除测试假象）
echo "  [self-check] fake DLP /inspect 直连状态码: $(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:${FAKE_DLP_PORT}/inspect -d '{}' -m 5)"
MP=$(start_mitm "http://127.0.0.1:${FAKE_DLP_PORT}/inspect" "open" "5.0"); sleep 4
fire s4
echo "  --- addon 分支佐证 (mitm.log 尾部，应见 '判定异常 -> fail-closed' 而非 'unreachable') ---"
sudo grep -E "KIRO-FAILCLOSED|判定异常|不可达|dlp_error|dlp_unreachable" "$WORK/mitm.log" | tail -4
echo "  期望: code=503 + upstream_hit=no（即使 fail-open：HTTP 503=服务自认无法扫描，恒 closed）"
stop_mitm "$MP"

kill "$FDLP_PID" "$ECHO_PID" 2>/dev/null
echo
echo "===== teardown（生产 8443 未受影响）====="
echo "prod kiro-mitm: $(sudo systemctl is-active kiro-mitm)"
