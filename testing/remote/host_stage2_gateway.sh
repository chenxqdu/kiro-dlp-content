#!/usr/bin/env bash
# 阶段2 — LiteLLM 网关集成测(host 端)。本轮 46/46 通过的原始命令。
# 前提:litellm 容器已 up(compose 见 docker/docker-compose.gateway.yml),
#       gateway/test_gateway.py 已同步到实例(sync_gateway 或手动 scp/S3)。
# 若改过 engine/dlp 源码,先 `sudo docker restart litellm` 让挂载的 /app/dlp 重新加载。
set -e
cd /home/ec2-user/kiro-dlp/gateway

KEY=$(sudo docker inspect litellm \
      --format '{{range .Config.Env}}{{println .}}{{end}}' \
      | grep '^LITELLM_MASTER_KEY=' | cut -d= -f2-)

# 清空指标文件,便于跑完做 verdict 分布对账
sudo docker exec litellm sh -c ': > /metrics/dlp_gateway_metrics.jsonl'

python3 test_gateway.py --base-url http://localhost:4000/v1 --key "$KEY" \
  --fixtures ../engine/tests/fixtures --model llama-3.1-8b --suites 1,2,3,5
echo "GW_EXIT=$?"

echo '=== 指标复核:verdict 分布 + 网关内扫描延迟 ==='
sudo docker exec litellm python3 - <<'PY'
import json, collections, statistics as st
ls = [json.loads(l) for l in open('/metrics/dlp_gateway_metrics.jsonl')]
c = collections.Counter((x['kind'], x['verdict'], x.get('top_layer')) for x in ls)
print('总记录', len(ls))
for k, v in sorted(c.items()):
    print(k, v)
tot = sorted(x['latency_ms'].get('total', 0) for x in ls if x['kind'] == 'pre_call')
if tot:
    print('pre_call scan total ms: p50=%.1f p95=%.1f mean=%.1f n=%d'
          % (tot[len(tot)//2], tot[int(len(tot)*0.95)], st.mean(tot), len(tot)))
PY
