#!/usr/bin/env bash
# 把本地 engine/(dlp 源码 + tests + fixtures)同步到实例 /home/ec2-user/kiro-dlp/engine。
# SSM 传不动大 payload → 走 S3 presigned URL 中转(实例侧只需 curl,无需 S3 权限)。
# 用法: ./sync_engine.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"   # 先固化绝对路径:后面 cd 会使相对 $0 失效
# remote/ -> testing/ -> 方案一-litellm-gateway/ -> 仓库根(engine/ 是两方案共享层,留在根)
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
BUCKET="${KIRO_DLP_S3_BUCKET:?请设置 KIRO_DLP_S3_BUCKET 为你自有的中转 bucket}"
KEY="kiro-dlp/engine_sync_$(date +%s).tgz"

cd "$REPO_ROOT/engine"
tar czf /tmp/engine_sync.tgz dlp/*.py tests/*.py tests/fixtures/*.json tests/fixtures_layers/*.json
aws s3 cp /tmp/engine_sync.tgz "s3://$BUCKET/$KEY" \
  --profile default --region us-west-2 --only-show-errors
URL=$(aws s3 presign "s3://$BUCKET/$KEY" --profile default --region us-west-2 --expires-in 900)

HOST_SCRIPT=$(mktemp)
cat > "$HOST_SCRIPT" <<EOF
set -e
cd /home/ec2-user/kiro-dlp
curl -sf -o /tmp/engine_sync.tgz '$URL'
tar xzf /tmp/engine_sync.tgz -C engine/
echo "engine synced: \$(ls engine/dlp/*.py | wc -l) dlp files, \$(ls engine/tests/fixtures/*.json | wc -l) suite fixtures, \$(ls engine/tests/fixtures_layers/*.json | wc -l) layer fixtures"
EOF

"$SCRIPT_DIR/ssm_exec.sh" "$HOST_SCRIPT" 300
rm -f "$HOST_SCRIPT"
