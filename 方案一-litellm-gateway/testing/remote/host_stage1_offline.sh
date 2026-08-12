#!/usr/bin/env bash
#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
# 阶段1 — 离线 56 条矩阵(host 端,经 ssm_exec.sh 投递)。
# 本轮 56/56 通过的原始命令。exit 码 = run_offline 的硬门(有 fail / 套件2 误报>0 /
# 套件1 漏拦>0 → 非 0)。
#
# 关键纪律:跑前必清孤儿容器 —— ssm cancel-command 不杀容器,残留容器会抢
# presidio-analyzer 的单核,把延迟计时打飞到 14-29s/条(本轮实测踩过)。
set -e
cd /home/ec2-user/kiro-dlp

sudo docker ps -q --filter ancestor=kiro-dlp-engine:latest | xargs -r sudo docker rm -f

echo '### FULL 56 RUN ###'
sudo docker run --rm --network docker_default \
  -v /home/ec2-user/kiro-dlp/engine:/app/engine -w /app/engine \
  kiro-dlp-engine:latest python3 -m tests.run_offline --no-color
echo "FULL_EXIT=$?"

# 分套件调试(定位单套件问题时用):
#   ... python3 -m tests.run_offline --suite N --no-color --verbose
# --verbose 会对失败项打印每条 hit 的 layer/rule/entity/action/source。
