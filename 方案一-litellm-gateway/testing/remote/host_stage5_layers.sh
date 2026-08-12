#!/usr/bin/env bash
#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
# 阶段5 — 分层完备测试(host 端,经 ssm_exec.sh 投递)。
# 与阶段1(run_offline 场景矩阵)互补:这里逐层逐规则验正例/豁免/边界。
#
# 三段:
#   ① presidio health 探测(确认 analyzer 可达,否则 L3 会 SKIP 而非 fail)
#   ② 分层全量(带 Presidio,不含 Bedrock)—— L3 真跑,L4-Bedrock 向量 SKIP
#   ③ 仅 L4 --bedrock —— ⚠ 数据出 VPC,仅功能验证,非生产配置
#
# 纪律:跑前必清孤儿容器(ssm cancel 不杀容器,残留会抢 presidio 单核使延迟失真)。
# 不用 set -e:要在任一段非 0 时仍打印后续 EXIT 码,故手动捕获。
set -uo pipefail
cd /home/ec2-user/kiro-dlp

# ★ 清孤儿容器 —— 必须【按名字排除常驻服务】,绝不能裸用 --filter ancestor=。
#   ancestor= 匹配的是【镜像】,而方案二常驻的 kiro-dlp-http(:9000 inspect 服务)跑的正是同一镜像
#   kiro-dlp-engine:latest —— 2026-08-05 裸用该 filter 把它一并 rm -f 了,而本阶段测试【全绿无异常】,
#   只有去看方案二才发现 :9000 不可达(复原:docker compose -f docker-compose.dlp-http.yml up -d)。
#   真正的孤儿来自 `docker run --rm`(随机名),按名字白名单排除常驻服务即可精确清理。
KEEP_RE='^(kiro-dlp-http|litellm|litellm-nodlp|presidio-analyzer)$'
sudo docker ps --filter ancestor=kiro-dlp-engine:latest --format '{{.ID}} {{.Names}}' \
  | awk -v keep="$KEEP_RE" '$2 !~ keep {print $1}' \
  | xargs -r sudo docker rm -f

echo '### ① presidio-analyzer health 探测 ###'
sudo docker run --rm --network docker_default kiro-dlp-engine:latest \
  python3 -c "import urllib.request as u; print(u.urlopen('http://presidio-analyzer:5002/health', timeout=5).read().decode())" \
  || echo 'HEALTH_PROBE_FAILED(→L3 将 SKIP)'

echo
echo '### ② 分层全量(带 Presidio,不含 Bedrock)###'
sudo docker run --rm --network docker_default \
  -v /home/ec2-user/kiro-dlp/engine:/app/engine -w /app/engine \
  kiro-dlp-engine:latest python3 -m tests.run_layers --no-color
echo "LAYERS_EXIT=$?"

echo
echo '### ②b 仅 L3 隔离复跑(聚焦 Presidio 逐实体)###'
sudo docker run --rm --network docker_default \
  -v /home/ec2-user/kiro-dlp/engine:/app/engine -w /app/engine \
  kiro-dlp-engine:latest python3 -m tests.run_layers --layer L3 --no-color
echo "L3_EXIT=$?"

echo
echo '### ③ 仅 L4 --bedrock(⚠ 数据出 VPC,仅功能验证,非生产)###'
sudo docker run --rm --network docker_default \
  -v /home/ec2-user/kiro-dlp/engine:/app/engine -w /app/engine \
  kiro-dlp-engine:latest python3 -m tests.run_layers --layer L4 --bedrock --no-color
echo "L4_BEDROCK_EXIT=$?"
