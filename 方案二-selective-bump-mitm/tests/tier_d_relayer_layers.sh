#!/usr/bin/env bash
#############################################
# Tier D —— 逐层探针 · 通过【真实代理链路】重验 L0–L3.5(在验证节点 EC2 上执行)
#
# 定位:Tier B 只用 PASS/REDACT/BLOCK 三条语料证明"裁决作用在 wire 字节上";
#      本层把这条同样的真实链路【按引擎层拆开】,每层至少一条探针,双断言 verdict + top_layer。
#
# 与方案一 stage5(engine/tests/run_layers.py,`import dlp` 直调各层 scan() 单测)的本质区别:
#      本脚本每个探针都【穿过真实 mitmproxy addon → HTTP → VPC 内 DLP inspect 服务(9000)】,
#      再由 echo 上游做字节级取证。证明的是【部署链路 + addon + 引擎】联动,而非仅引擎函数。
#      → stage5 证明"规则对";本层证明"规则在真链路上仍然对"。两者互补,都要跑。
#
# 拓扑(与生产 443→8443 完全隔离,绝不干扰已验证链路):
#   curl(信任 root, --resolve bump 域:9443:127.0.0.1)
#     └─TLS→ 临时 mitmdump 127.0.0.1:9443 (reverse→http://127.0.0.1:18080, 同一 kiro_addon.py)
#              └─(addon 解密→POST 明文 body 到 172.31.27.174:9000/inspect→裁决)
#                    ├─ PASS  : 原样转发 → echo 落盘 == 输入(逐字节)
#                    ├─ REDACT: 改写后转发 → echo 落盘中敏感明文消失
#                    └─ BLOCK : 合成 400 短路 → echo 从未被命中(上游 body 文件不存在)
#
# 逐层判读:每个探针针对某一层设计,期望 verdict + 期望 top_layer 双断言。
#   top_layer 来自 addon 决策日志 KIRO-BLOCK/REDACT top=Lx(引擎聚合的"最低有效层")。
#############################################
set -uo pipefail

CERTS=/etc/mitm/certs
BUMP=runtime.us-east-1.kiro.dev
ECHO_PORT=18080
MITM_PORT=9443
WORK=/tmp/relayer_layers
DLP_URL=http://172.31.27.174:9000/inspect
PATHQ="/generateAssistantResponse/GenerateAssistantResponse"

sudo rm -rf "$WORK"; mkdir -p "$WORK"
UP_BODY="$WORK/upstream_body.bin"

############## 0. inspect 健康预检(链路前置) ##############
echo "===== PRECHECK: DLP inspect health ====="
curl -sS --max-time 5 http://172.31.27.174:9000/health -w " [http=%{http_code}]\n" 2>&1 || {
  echo "FATAL: DLP inspect 9000 不可达,无法验证"; exit 1; }
echo

############## 1. echo 上游:把收到的 POST body 原样落盘 ##############
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

############## 2. 探针 JSON 生成(python 构造,避免手写转义地狱) ##############
# 每个探针 content 放进 CodeWhisperer 信封的 userInputMessage.content(真实用户内容字段)。
python3 - "$WORK" <<'PY'
import json, os, sys
work = sys.argv[1]
def env(content):
    return {"conversationState":{"currentMessage":{"userInputMessage":{"content":content}}}}

# name, content, expect_verdict, expect_top, sensitive_marker(REDACT 判上游消失;非 REDACT 留空)
CASES = [
    ("PASS_quicksort",
     "Please write a quicksort function in Python, with brief comments.",
     "PASS", "", ""),
    ("L0_BLOCK_aws_ak",
     "Here is my AWS key AKIAZ3QK7NABCDEF9WK7, please help me debug the config.",
     "BLOCK", "L0", ""),
    ("L0_REDACT_cn_phone",
     "我叫张伟，电话 13800138000，帮我起草一封请假邮件。",
     "REDACT", "L0", "13800138000"),
    ("L1_BLOCK_pem_privkey",
     "帮我调试这段密钥:\n-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34\nGkxFhD9SJ0Nu3\n-----END RSA PRIVATE KEY-----",
     "BLOCK", "L1", ""),
    ("L2_BLOCK_high_entropy",
     "config file: api_key = \"Xq7Kp2Bv9Zm4Rt6Yw8Nc1Ld3Pf5Gj0As\" please review",
     "BLOCK", "L2", ""),
    ("L3_REDACT_credit_card",
     "Please verify my card number 4539578763621486 for the payment.",
     "REDACT", "L3", "4539578763621486"),
    ("L35_BLOCK_glossary",
     "Let's discuss the roadmap for Project Nightingale next quarter.",
     "BLOCK", "L3.5", ""),
    ("L35_REDACT_ticket",
     "Please check ticket SEV1-12345 for the incident details.",
     "REDACT", "L3.5", "SEV1-12345"),
]
os.makedirs(os.path.join(work, "cases"), exist_ok=True)
manifest = []
for name, content, ev, et, marker in CASES:
    p = os.path.join(work, "cases", name + ".json")
    with open(p, "w") as f:
        json.dump(env(content), f, ensure_ascii=False)
    manifest.append("%s|%s|%s|%s" % (name, ev, et, marker))
with open(os.path.join(work, "manifest.txt"), "w") as f:
    f.write("\n".join(manifest) + "\n")
print("generated %d cases" % len(CASES))
PY

############## 3. 专用临时 mitmdump(reverse→echo,加载生产同款 addon) ##############
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

echo "===== relayer mitmdump boot log (tail) ====="
sudo tail -n 6 "$WORK/mitm.log"
echo

############## 4. 逐探针执行 + 双断言(verdict + top_layer) ##############
PASS_CNT=0; FAIL_CNT=0
RESULTS="$WORK/results.txt"; : > "$RESULTS"

run_case () {
  local name="$1" ev="$2" et="$3" marker="$4"
  local file="$WORK/cases/$name.json"
  echo "=================== $name (expect verdict=$ev top=${et:-N/A}) ==================="
  sudo rm -f "$UP_BODY"
  local pre_lines; pre_lines=$(sudo wc -l < "$WORK/mitm.log" 2>/dev/null || echo 0)

  local http_code
  http_code=$(curl -s -o "$WORK/resp_$name.bin" -w '%{http_code}' \
    --cacert "$CERTS/root.crt" \
    --resolve "${BUMP}:${MITM_PORT}:127.0.0.1" \
    -X POST "https://${BUMP}:${MITM_PORT}${PATHQ}" \
    -H 'Content-Type: application/x-amz-json-1.1' \
    -H 'Authorization: Bearer FAKE-OIDC-TOKEN-relayer' \
    -H "X-Amz-Target: AmazonQDeveloperStreamingService.GenerateAssistantResponse" \
    --data-binary @"$file" -m 25)

  # 抓本 case 新增的 addon 决策行
  local dec_line
  dec_line=$(sudo tail -n +$((pre_lines+1)) "$WORK/mitm.log" 2>/dev/null | grep -aE "KIRO-(BLOCK|REDACT|FAILCLOSED)" | tail -1)
  local got_top
  got_top=$(printf '%s' "$dec_line" | grep -aoE "top=[A-Za-z0-9.]+" | head -1 | cut -d= -f2)

  echo "client_http_code=$http_code"
  echo "addon_decision: ${dec_line:-<none (PASS 或未打印)>}"

  # 判读 verdict + 取证
  local got_verdict="?" upstream_state fp="FAIL"
  if [[ -f "$UP_BODY" ]]; then
    upstream_state="HIT(len=$(sudo stat -c%s "$UP_BODY"))"
  else
    upstream_state="NONE(短路)"
  fi

  case "$ev" in
    PASS)
      # 200 + 上游逐字节一致 + 无 BLOCK/REDACT 决策行
      if [[ "$http_code" == "200" && -f "$UP_BODY" ]] && sudo cmp -s "$UP_BODY" "$file" && [[ -z "$dec_line" ]]; then
        got_verdict="PASS"; fp="OK"
      fi
      ;;
    REDACT)
      # 200 + 上游存在 + 敏感明文消失 + 决策行 KIRO-REDACT + top 匹配
      if [[ "$http_code" == "200" && -f "$UP_BODY" ]] \
         && ! sudo grep -aqF "$marker" "$UP_BODY" \
         && printf '%s' "$dec_line" | grep -aq "KIRO-REDACT" \
         && [[ "$got_top" == "$et" ]]; then
        got_verdict="REDACT"; fp="OK"
      fi
      ;;
    BLOCK)
      # 400 + 上游零命中 + 决策行 KIRO-BLOCK + top 匹配
      if [[ "$http_code" == "400" && ! -f "$UP_BODY" ]] \
         && printf '%s' "$dec_line" | grep -aq "KIRO-BLOCK" \
         && [[ "$got_top" == "$et" ]]; then
        got_verdict="BLOCK"; fp="OK"
      fi
      ;;
  esac

  # ★ 失败必须打 ❌:run_all.sh 用 `grep -qE '❌|FATAL'` 判层,只写 "FAIL" 字样会被判成 PASS。
  local mark; [[ "$fp" == "OK" ]] && mark="✓ OK" || mark="❌ FAIL"
  echo "upstream=$upstream_state  got_top=${got_top:-N/A}  verdict_judged=$got_verdict  => $mark"
  echo "$name|expect=$ev/${et:-NA}|http=$http_code|top=${got_top:-NA}|upstream=$upstream_state|$mark" >> "$RESULTS"
  if [[ "$fp" == "OK" ]]; then PASS_CNT=$((PASS_CNT+1)); else FAIL_CNT=$((FAIL_CNT+1)); fi
  echo
}

while IFS='|' read -r name ev et marker; do
  [[ -z "$name" ]] && continue
  run_case "$name" "$ev" "$et" "$marker"
done < "$WORK/manifest.txt"

############## 5. 汇总 ##############
echo "=================== 逐层链路重验 汇总 ==================="
cat "$RESULTS"
echo "-------------------------------------------------------"
echo "PASS=$PASS_CNT  FAIL=$FAIL_CNT  TOTAL=$((PASS_CNT+FAIL_CNT))"
if [[ "$FAIL_CNT" -gt 0 ]]; then echo "Tier D 总判: ❌ 有探针未通过"; else echo "Tier D 总判: ✓ 全绿"; fi
echo

############## 6. 拆除临时实例(生产 8443 不受影响) ##############
sudo kill "$MITM_PID" 2>/dev/null; kill "$ECHO_PID" 2>/dev/null
sudo pkill -f "mitmdump.*${MITM_PORT}" 2>/dev/null
pkill -f "echo_upstream.py" 2>/dev/null
sleep 1
echo "prod kiro-mitm still: $(sudo systemctl is-active kiro-mitm)"
echo "relayer-layers done."
exit 0
