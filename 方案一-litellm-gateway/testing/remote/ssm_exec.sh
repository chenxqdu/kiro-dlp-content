#!/usr/bin/env bash
# 通用 SSM 执行器:把本地 bash 脚本整体 base64 后经 SSM RunShellScript 在实例上执行,
# 轮询到结束并取回 stdout/stderr。
#
# 为什么这么绕:SSM 的 --parameters shorthand 对含空格/引号/中文的 commands 会
# choke(ValidationException / Expected ','),实测唯一稳妥路径是
#   echo <b64> | base64 -d | bash
# 让 SSM 只见到一个纯 ASCII 单词。
#
# 用法: ./ssm_exec.sh <host脚本文件> [超时秒,默认900]
# 依赖: aws CLI(profile default, us-west-2);实例须 SSM Online。
set -euo pipefail

INSTANCE_ID="${KIRO_DLP_INSTANCE:?请设置 KIRO_DLP_INSTANCE 为目标测试实例 ID}"
REGION="us-west-2"
PROFILE="default"
SCRIPT_FILE="${1:?用法: ssm_exec.sh <host脚本文件> [超时秒]}"
EXEC_TIMEOUT="${2:-900}"

B64=$(base64 < "$SCRIPT_FILE" | tr -d '\n')
PARAMS=$(python3 - "$B64" "$EXEC_TIMEOUT" <<'PY'
import json, sys
print(json.dumps({"commands": ["echo " + sys.argv[1] + " | base64 -d | bash"],
                  "executionTimeout": [sys.argv[2]]}))
PY
)

CID=$(aws ssm send-command --profile "$PROFILE" --region "$REGION" \
  --instance-ids "$INSTANCE_ID" \
  --document-name AWS-RunShellScript \
  --parameters "$PARAMS" \
  --query 'Command.CommandId' --output text)
echo "CommandId=$CID" >&2

while :; do
  sleep 8
  ST=$(aws ssm get-command-invocation --profile "$PROFILE" --region "$REGION" \
       --command-id "$CID" --instance-id "$INSTANCE_ID" \
       --query 'Status' --output text 2>/dev/null || echo Pending)
  echo "status=$ST" >&2
  case "$ST" in Success|Failed|Cancelled|TimedOut) break;; esac
done

echo "===== STDOUT ====="
aws ssm get-command-invocation --profile "$PROFILE" --region "$REGION" \
  --command-id "$CID" --instance-id "$INSTANCE_ID" \
  --query 'StandardOutputContent' --output text
echo "===== STDERR =====" >&2
aws ssm get-command-invocation --profile "$PROFILE" --region "$REGION" \
  --command-id "$CID" --instance-id "$INSTANCE_ID" \
  --query 'StandardErrorContent' --output text >&2

[ "$ST" = "Success" ]
