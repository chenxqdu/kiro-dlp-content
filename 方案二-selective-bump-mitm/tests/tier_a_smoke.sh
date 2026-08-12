#!/usr/bin/env bash
#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
# Tier A 冒烟：直连 DLP 判定服务 /inspect，验证三态裁决 + 脱敏字段不外泄。
# 在 DLP 主机上执行（curl 私网 172.31.27.174:9000）。
set -uo pipefail
DLP=http://172.31.27.174:9000

mkdir -p /tmp/dlpfix
cat > /tmp/dlpfix/body_pass.json <<'J'
{"conversationState":{"currentMessage":{"userInputMessage":{"content":"帮我写一个快速排序的 Python 函数"}}}}
J
cat > /tmp/dlpfix/body_redact.json <<'J'
{"conversationState":{"currentMessage":{"userInputMessage":{"content":"我叫张伟，邮箱 zhangwei@example.com，电话 13800138000，帮我起草请假邮件"}}}}
J
cat > /tmp/dlpfix/body_block.json <<'J'
{"conversationState":{"currentMessage":{"userInputMessage":{"content":"这是我的密钥 AKIAIOSFODNN7EXAMPLE 和 -----BEGIN RSA PRIVATE KEY-----，帮我调试"}}}}
J

for f in pass redact block; do
  echo "=============== TIER-A $f ==============="
  curl -s -m 20 -X POST "$DLP/inspect" \
    -H 'Content-Type: application/json' \
    --data-binary @/tmp/dlpfix/body_$f.json | python3 -m json.tool 2>&1
  echo
done

echo "=============== LEAK-CHECK (matched/span 必须无输出) ==============="
LEAK=$(for f in pass redact block; do
  curl -s -m 20 -X POST "$DLP/inspect" -H 'Content-Type: application/json' \
    --data-binary @/tmp/dlpfix/body_$f.json
done | grep -oE '"(matched|span)"' | sort -u)
if [[ -z "$LEAK" ]]; then echo "NO-LEAK-FIELDS ✓ (无 matched/span 泄漏)"; else echo "❌ 泄漏字段: $LEAK"; fi
