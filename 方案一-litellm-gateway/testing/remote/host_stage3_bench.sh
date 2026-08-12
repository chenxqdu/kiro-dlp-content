#!/usr/bin/env bash
#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
# 阶段3 — 开/关 DLP 压测 + docker stats CPU 归因(host 端)。本轮原始命令。
# 前提:litellm(:4000, DLP on)与 litellm-nodlp(:4001, 无 guardrail 对照)都在跑。
# 输出 JSON 行(bench_gateway.py),stats 采样落 /tmp/bench_stats.txt。
set -e
cd /home/ec2-user/kiro-dlp/gateway

KEY=$(sudo docker inspect litellm --format '{{range .Config.Env}}{{println .}}{{end}}' \
      | grep '^LITELLM_MASTER_KEY=' | cut -d= -f2-)
KEY2=$(sudo docker inspect litellm-nodlp --format '{{range .Config.Env}}{{println .}}{{end}}' \
      | grep '^LITELLM_MASTER_KEY=' | cut -d= -f2-)

# 后台 stats 采样(5s 一次 × 60 = 5 分钟窗口,覆盖两轮 bench)
: > /tmp/bench_stats.txt
( for i in $(seq 1 60); do
    sudo docker stats --no-stream \
      --format '{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}' >> /tmp/bench_stats.txt
    echo --- >> /tmp/bench_stats.txt
    sleep 5
  done ) &
STATS_PID=$!

echo "### DLP-ON ###"
python3 bench_gateway.py --base-url http://localhost:4000/v1 --key "$KEY" --n 30 --label dlp-on
echo "### DLP-OFF ###"
python3 bench_gateway.py --base-url http://localhost:4001/v1 --key "$KEY2" --n 30 --label dlp-off

kill $STATS_PID 2>/dev/null || true
echo "### STATS 采样(头尾各 30 行) ###"
head -30 /tmp/bench_stats.txt; echo ......; tail -30 /tmp/bench_stats.txt
