#!/usr/bin/env bash
#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
#############################################
# §4 Tier C —— 真实上游交叉核对（在验证节点 EC2 执行，走【生产】443→8443→真实 Kiro）
#
# 与 Tier B（本地 echo 上游）互补：Tier C 打【真实 runtime.us-east-1.kiro.dev】，配【假 Bearer】。
# 目的：证明 BLOCK 是在触达真实 Kiro 端点【之前】短路的（机密零出网），而非"发出去又被拒"。
#
# 四向交叉核对（靠响应来源区分）：
#   PASS  (普通内容+假token) : 请求真到 Kiro -> Kiro 返 403/401（token 无效）
#                              => 证明完整转发路径 + 真实上游 TLS 腿贯通
#   BLOCK (含 RSA 私钥+假token): 我方合成 400 CorpDLPBlockedException（x-amzn-ErrorType 头）
#                              => 在触达真实 Kiro 前短路，含密钥内容从未出网
#
# 判据：BLOCK 的响应必须带我方特征头 x-amzn-ErrorType: CorpDLPBlockedException，
#       且 __type=CorpDLPBlockedException；PASS 的响应必须来自 AWS（无我方特征头，
#       状态码为 4xx 鉴权拒绝或 AWS 风格错误体）。两者来源可区分 = BLOCK 未出网。
#
# ★ 全程走生产 443（本机 loopback，SSM 自测，无公网 443），生产 mitm 不改动。
#############################################
set -uo pipefail
CERTS=/etc/mitm/certs
BUMP=runtime.us-east-1.kiro.dev
WORK=/tmp/tierc
sudo rm -rf "$WORK"; mkdir -p "$WORK"

cat > "$WORK/pass.json" <<'J'
{"conversationState":{"currentMessage":{"userInputMessage":{"content":"请解释一下 TCP 三次握手"}}}}
J
cat > "$WORK/block.json" <<'J'
{"conversationState":{"currentMessage":{"userInputMessage":{"content":"帮我调试这段：-----BEGIN RSA PRIVATE KEY-----MIIEpAIBAAKCAQEA-----END RSA PRIVATE KEY----- 还有 AKIAIOSFODNN7EXAMPLE"}}}}
J

fire () {  # $1 label  $2 file
  echo "=================== TIER-C $1 (真实上游 + 假token) ==================="
  # -D 抓响应头，-o 抓响应体，-w 状态码；走生产 443（loopback）
  local code
  code=$(curl -s -D "$WORK/hdr_$1.txt" -o "$WORK/body_$1.bin" -w '%{http_code}' \
    --cacert "$CERTS/root.crt" --resolve "${BUMP}:443:127.0.0.1" \
    -X POST "https://${BUMP}:443/generateAssistantResponse" \
    -H 'Content-Type: application/x-amz-json-1.1' \
    -H 'Authorization: Bearer FAKE-OIDC-TOKEN-tierc-invalid' \
    -H "X-Amz-Target: AmazonQDeveloperStreamingService.GenerateAssistantResponse" \
    --data-binary @"$2" -m 30)
  echo "  http_code=$code"
  echo "  --- 响应头关键行 ---"
  grep -iE "^HTTP/|x-amzn-ErrorType|x-amzn-RequestId|x-amz-|server:|content-type:" "$WORK/hdr_$1.txt" 2>/dev/null | head -12
  echo "  --- 响应体 (前 240B) ---"
  head -c 240 "$WORK/body_$1.bin" 2>/dev/null; echo
  echo
}

fire pass  "$WORK/pass.json"
fire block "$WORK/block.json"

echo "=================== TIER-C 交叉核对断言 ==================="
# BLOCK：必须是我方合成（x-amzn-ErrorType: CorpDLPBlockedException）
if grep -qi "x-amzn-ErrorType: *CorpDLPBlockedException" "$WORK/hdr_block.txt" \
   && grep -q "CorpDLPBlockedException" "$WORK/body_block.bin"; then
  echo "BLOCK: 我方短路 (CorpDLPBlockedException 特征头+体) ✓ —— 含密钥内容未触达真实 Kiro"
else
  echo "BLOCK: ❌ 未见我方短路特征头，疑似流量已出网"
fi

# PASS：必须【不】带我方特征头（响应来自 AWS，证明真到了上游）
if ! grep -qi "CorpDLPBlockedException" "$WORK/hdr_pass.txt" \
   && ! grep -qi "dlp_fail_closed" "$WORK/body_pass.bin"; then
  echo "PASS: 响应非我方合成（来自真实上游/鉴权层）✓ —— 转发路径+真实 TLS 腿贯通"
  echo "      (说明：假 token 下真实 Kiro 预期返回 401/403 鉴权拒绝，这正是'请求确实到达了上游'的证据)"
else
  echo "PASS: ⚠ 响应疑似我方合成（可能 fail-closed），需查 DLP 判定服务连通性"
fi

echo
echo "prod kiro-mitm: $(sudo systemctl is-active kiro-mitm)  nginx: $(sudo systemctl is-active nginx)"
