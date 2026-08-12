#!/usr/bin/env bash
#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
#############################################
# Tier B —— wire-byte 证据（在验证节点 EC2 上执行）
#
# 目标：证明 addon 的三态裁决真正作用在【发往上游的字节流】上，而非只停留在判定服务侧。
#
# 拓扑（与生产 443→8443 完全隔离，绝不干扰已验证链路）：
#   curl(信任 root, --resolve bump 域:9443:127.0.0.1)
#     └─TLS→ 临时 mitmdump 127.0.0.1:9443  (reverse → http://127.0.0.1:18080, 同一个 kiro_addon.py)
#              └─(addon 解密→调 DLP 判定→PASS/REDACT/BLOCK)→ echo 上游 127.0.0.1:18080
#                    └─ echo 把【实际收到的 body】原样落盘 /tmp/tierb/upstream_body.bin
#
# 判读：
#   PASS   : client 200；upstream_body == 输入（逐字节）
#   REDACT : client 200；upstream_body 中 PII 已被 mask（与输入不同，且原文消失）
#   BLOCK  : client 400 CorpDLPBlockedException；upstream_body 文件【不存在】（上游从未被命中）
#############################################
set -uo pipefail

CERTS=/etc/mitm/certs
BUMP=runtime.us-east-1.kiro.dev
ECHO_PORT=18080
MITM_PORT=9443
WORK=/tmp/tierb
DLP_URL=http://172.31.27.174:9000/inspect

sudo rm -rf "$WORK"; mkdir -p "$WORK"
UP_BODY="$WORK/upstream_body.bin"

############## 1. echo 上游：把收到的 POST body 原样落盘 ##############
cat > "$WORK/echo_upstream.py" <<PY
import http.server, socketserver, sys
UP_BODY = "$UP_BODY"
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n) if n else b""
        with open(UP_BODY, "wb") as f:
            f.write(body)
        sys.stderr.write("ECHO-UPSTREAM-HIT path=%s len=%d\n" % (self.path, len(body)))
        sys.stderr.flush()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Length","2"); self.end_headers(); self.wfile.write(b"ok")
with socketserver.TCPServer(("127.0.0.1", $ECHO_PORT), H) as s:
    s.serve_forever()
PY

python3 "$WORK/echo_upstream.py" >"$WORK/echo.log" 2>&1 &
ECHO_PID=$!
sleep 1

############## 2. 专用临时 mitmdump（reverse→echo，加载同一 addon） ##############
# 用生产同款 flags；上游改为本地 echo；端口 9443 与生产 8443 隔离。
sudo env \
  HOME=/etc/mitm \
  PYTHONUNBUFFERED=1 \
  DLP_INSPECT_URL="$DLP_URL" \
  MITM_BUMP_DOMAIN="$BUMP" \
  DLP_FAIL_MODE=closed \
  DLP_TIMEOUT=8.0 \
  /opt/mitm-venv/bin/mitmdump \
    --mode reverse:http://127.0.0.1:${ECHO_PORT}@127.0.0.1:${MITM_PORT} \
    --set keep_host_header=true \
    --set upstream_cert=false \
    --set connection_strategy=lazy \
    --set confdir=${CERTS} \
    -s /etc/mitm/kiro_addon.py \
    >"$WORK/mitm.log" 2>&1 &
MITM_PID=$!
sleep 4

echo "===== Tier B mitmdump boot log (tail) ====="
sudo tail -n 8 "$WORK/mitm.log"
echo

############## 3. 三态请求体 ##############
cat > "$WORK/pass.json" <<'J'
{"conversationState":{"currentMessage":{"userInputMessage":{"content":"帮我写一个快速排序的 Python 函数"}}}}
J
cat > "$WORK/redact.json" <<'J'
{"conversationState":{"currentMessage":{"userInputMessage":{"content":"我叫张伟，电话 13800138000，帮我起草请假邮件"}}}}
J
cat > "$WORK/block.json" <<'J'
{"conversationState":{"currentMessage":{"userInputMessage":{"content":"这是我的密钥 AKIAIOSFODNN7EXAMPLE 和 -----BEGIN RSA PRIVATE KEY-----，帮我调试"}}}}
J

PATHQ="/generateAssistantResponse/GenerateAssistantResponse"
run_case () {
  local name="$1" file="$2"
  echo "=================== TIER-B $name ==================="
  sudo rm -f "$UP_BODY"     # 清空上游捕获，用于判定 BLOCK 是否短路
  local http_code
  http_code=$(curl -s -o "$WORK/client_resp_$name.bin" -w '%{http_code}' \
    --cacert "$CERTS/root.crt" \
    --resolve "${BUMP}:${MITM_PORT}:127.0.0.1" \
    -X POST "https://${BUMP}:${MITM_PORT}${PATHQ}" \
    -H 'Content-Type: application/x-amz-json-1.1' \
    -H 'Authorization: Bearer FAKE-OIDC-TOKEN-tierb' \
    -H "X-Amz-Target: AmazonQDeveloperStreamingService.GenerateAssistantResponse" \
    --data-binary @"$file" -m 25)
  echo "client_http_code=$http_code"
  echo "--- client response (first 300B) ---"
  sudo head -c 300 "$WORK/client_resp_$name.bin" 2>/dev/null; echo
  if [[ -f "$UP_BODY" ]]; then
    echo "--- UPSTREAM RECEIVED (len=$(sudo stat -c%s "$UP_BODY") ) ---"
    sudo cat "$UP_BODY"; echo
  else
    echo "--- UPSTREAM RECEIVED: <NONE> (上游未被命中 = 已在代理侧短路) ---"
  fi
  echo
}

run_case pass   "$WORK/pass.json"
run_case redact "$WORK/redact.json"
run_case block  "$WORK/block.json"

############## 4. 断言汇总 ##############
echo "=================== TIER-B ASSERTIONS ==================="
# PASS：上游 body 必须与输入逐字节一致
sudo rm -f "$UP_BODY"; curl -s -o /dev/null --cacert "$CERTS/root.crt" \
  --resolve "${BUMP}:${MITM_PORT}:127.0.0.1" -X POST "https://${BUMP}:${MITM_PORT}${PATHQ}" \
  -H 'Content-Type: application/x-amz-json-1.1' -H 'Authorization: Bearer FAKE' \
  -H "X-Amz-Target: AmazonQDeveloperStreamingService.GenerateAssistantResponse" \
  --data-binary @"$WORK/pass.json" -m 25
if sudo cmp -s "$UP_BODY" "$WORK/pass.json"; then echo "PASS: upstream==input 逐字节一致 ✓"; else echo "PASS: ❌ 上游 body 与输入不一致"; fi

# REDACT：上游 body 里明文电话必须消失
sudo rm -f "$UP_BODY"; curl -s -o /dev/null --cacert "$CERTS/root.crt" \
  --resolve "${BUMP}:${MITM_PORT}:127.0.0.1" -X POST "https://${BUMP}:${MITM_PORT}${PATHQ}" \
  -H 'Content-Type: application/x-amz-json-1.1' -H 'Authorization: Bearer FAKE' \
  -H "X-Amz-Target: AmazonQDeveloperStreamingService.GenerateAssistantResponse" \
  --data-binary @"$WORK/redact.json" -m 25
if [[ -f "$UP_BODY" ]] && ! sudo grep -q "13800138000" "$UP_BODY"; then
  echo "REDACT: 上游 body 明文电话已消失 ✓"; else echo "REDACT: ❌ 上游仍含明文电话或未命中上游"; fi

# BLOCK：上游必须完全没被命中
sudo rm -f "$UP_BODY"; BC=$(curl -s -o /dev/null -w '%{http_code}' --cacert "$CERTS/root.crt" \
  --resolve "${BUMP}:${MITM_PORT}:127.0.0.1" -X POST "https://${BUMP}:${MITM_PORT}${PATHQ}" \
  -H 'Content-Type: application/x-amz-json-1.1' -H 'Authorization: Bearer FAKE' \
  -H "X-Amz-Target: AmazonQDeveloperStreamingService.GenerateAssistantResponse" \
  --data-binary @"$WORK/block.json" -m 25)
if [[ ! -f "$UP_BODY" && "$BC" == "400" ]]; then echo "BLOCK: 上游零命中 + client 400 ✓"; else echo "BLOCK: ❌ code=$BC upstream_hit=$([[ -f $UP_BODY ]] && echo yes || echo no)"; fi

############## 5. 拆除临时实例（生产 8443 不受影响） ##############
echo
echo "===== teardown tier B (prod mitm on 8443 untouched) ====="
sudo kill "$MITM_PID" 2>/dev/null; kill "$ECHO_PID" 2>/dev/null
sleep 1
echo "prod kiro-mitm still: $(sudo systemctl is-active kiro-mitm)"
echo "tier-b done."
