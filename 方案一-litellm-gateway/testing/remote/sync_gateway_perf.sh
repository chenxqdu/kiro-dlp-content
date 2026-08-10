#!/usr/bin/env bash
# 把 fail-closed 版 dlp_guardrail.py + 性能测试资产(testing/perf/)+ gateway compose
# 同步到实例 /home/ec2-user/kiro-dlp。走 S3 presigned 中转(实例侧只 curl)。
#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
# 用法: KIRO_DLP_S3_BUCKET=<你的中转桶> ./sync_gateway_perf.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# remote/ -> testing/ -> 方案一-litellm-gateway/(网关与 perf 都在方案一目录下)
PLAN1_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# docker/ 是仓库根下与两方案并列的共享编排目录
REPO_ROOT="$(cd "$PLAN1_ROOT/.." && pwd)"
BUCKET="${KIRO_DLP_S3_BUCKET:?请设置 KIRO_DLP_S3_BUCKET 为你自有的中转 bucket}"
KEY="kiro-dlp/gateway_perf_sync_$(date +%s).tgz"

STAGE=$(mktemp -d)
mkdir -p "$STAGE/gateway" "$STAGE/testing/perf" "$STAGE/docker"
# fail-closed 版网关代码
cp "$PLAN1_ROOT/gateway/dlp_guardrail.py" "$STAGE/gateway/"
# 性能测试资产
cp "$PLAN1_ROOT/testing/perf/"*.py "$PLAN1_ROOT/testing/perf/"*.js \
   "$PLAN1_ROOT/testing/perf/"*.json "$PLAN1_ROOT/testing/perf/"*.yaml \
   "$PLAN1_ROOT/testing/perf/"*.sh "$STAGE/testing/perf/"
# gateway compose(含 DLP_L3_UNAVAILABLE_ACTION env)
cp "$REPO_ROOT/docker/docker-compose.gateway.yml" "$STAGE/docker/"

tar czf /tmp/gateway_perf_sync.tgz -C "$STAGE" .
rm -rf "$STAGE"
aws s3 cp /tmp/gateway_perf_sync.tgz "s3://$BUCKET/$KEY" \
  --profile default --region us-west-2 --only-show-errors
URL=$(aws s3 presign "s3://$BUCKET/$KEY" --profile default --region us-west-2 --expires-in 900)

HOST_SCRIPT=$(mktemp)
cat > "$HOST_SCRIPT" <<EOF
set -e
cd /home/ec2-user/kiro-dlp
curl -sf -o /tmp/gateway_perf_sync.tgz '$URL'
tar xzf /tmp/gateway_perf_sync.tgz -C .
chmod +x testing/perf/run_perf.sh 2>/dev/null || true
echo "== 已同步 =="
echo "gateway/dlp_guardrail.py fail-closed 标志: \$(grep -c _dispose gateway/dlp_guardrail.py) _dispose, \$(grep -c _forced_block_reason gateway/dlp_guardrail.py) _forced_block_reason"
echo "perf 资产: \$(ls testing/perf/)"
echo "gateway compose 含 L3_UNAVAILABLE_ACTION: \$(grep -c DLP_L3_UNAVAILABLE_ACTION docker/docker-compose.gateway.yml)"
EOF

"$SCRIPT_DIR/ssm_exec.sh" "$HOST_SCRIPT" 300
rm -f "$HOST_SCRIPT"
