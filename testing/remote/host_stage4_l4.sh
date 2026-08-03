#!/usr/bin/env bash
# 阶段4 — L4 Bedrock 异步告警标定(host 端)。本轮原始命令,分两步:
#   A. 直连标定:容器内跑 tests/l4_calibration.py(双模型 × 套件6,
#      断言"L4 开启也不污染同步 verdict")
#   B. 端到端:litellm 开 DLP_L4_BEDROCK=1 → 套件6 打网关 → 验异步告警落盘 → 还原 0
# ⚠ 红线:Bedrock = 数据出 VPC,仅功能验证,非生产配置(报告必须写明)。
set -e

echo '### A. 直连标定 ###'
cd /home/ec2-user/kiro-dlp
sudo docker ps -q --filter ancestor=kiro-dlp-engine:latest | xargs -r sudo docker rm -f
sudo docker run --rm --network docker_default \
  -v /home/ec2-user/kiro-dlp/engine:/app/engine -w /app/engine \
  kiro-dlp-engine:latest python3 -m tests.l4_calibration
echo "L4_EXIT=$?"

echo '### B. 端到端(网关开 L4) ###'
cd /home/ec2-user/kiro-dlp/docker
export $(sudo docker inspect litellm --format '{{range .Config.Env}}{{println .}}{{end}}' \
         | grep '^LITELLM_MASTER_KEY=')
export DLP_L4_BEDROCK=1
sudo -E docker compose -f docker-compose.yml -f docker-compose.gateway.yml up -d litellm
KEY=$LITELLM_MASTER_KEY
for i in $(seq 1 45); do sleep 2
  code=$(curl -s -o /dev/null -w '%{http_code}' \
         -H "Authorization: Bearer $KEY" http://localhost:4000/v1/models || true)
  [ "$code" = "200" ] && echo "healthy after $((i*2))s" && break
done
sudo docker exec litellm sh -c ': > /metrics/dlp_gateway_metrics.jsonl'

python3 - "$KEY" <<'PY'
import json, sys, time, urllib.request, urllib.error
key = sys.argv[1]
for c in json.load(open('/home/ec2-user/kiro-dlp/engine/tests/fixtures/suite6.json')):
    payload = json.dumps({"model": "llama-3.1-8b", "max_tokens": 8,
                          "messages": [{"role": "user", "content": c["content"]}]}).encode()
    req = urllib.request.Request("http://localhost:4000/v1/chat/completions", data=payload,
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + key}, method="POST")
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            code = r.status; r.read()
    except urllib.error.HTTPError as e:
        code = e.code; e.read()
    print(c["id"], "HTTP", code, "rtt_ms", round((time.perf_counter()-t0)*1000, 1))
PY

echo '--- 等 L4 异步落盘(最多 30s) ---'
for i in $(seq 1 15); do sleep 2
  n=$(sudo docker exec litellm sh -c \
      "grep -c l4_alert /metrics/dlp_gateway_metrics.jsonl 2>/dev/null" || echo 0)
  [ "$n" -ge 3 ] && break
done
sudo docker exec litellm sh -c "grep l4_alert /metrics/dlp_gateway_metrics.jsonl"
sudo docker logs --since 3m litellm 2>&1 | grep -a "DLP L4" | tail -8

echo '### 还原 DLP_L4_BEDROCK=0(标定完必做) ###'
export DLP_L4_BEDROCK=0
sudo -E docker compose -f docker-compose.yml -f docker-compose.gateway.yml up -d litellm
sleep 10
sudo docker exec litellm sh -c 'tr "\0" "\n" < /proc/1/environ | grep DLP_L4'
