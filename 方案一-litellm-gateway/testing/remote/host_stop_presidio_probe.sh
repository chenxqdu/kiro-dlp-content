#!/usr/bin/env bash
#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
# 停 Presidio 专项(fail-closed 核心验证,规格 D4 / 03 §9.4)。
# probe = 信用卡号 4539578763621486(公开 Luhn 合成串):健康时 top=L3,仅 Presidio
# NER 可检(本地层 L0/L1/L2/L3.5 判不出)——正是 fail-open 会静默泄漏、fail-closed 要
# 堵死的那一类。裁决以网关 metrics jsonl 的 verdict/forced_block 为准(权威信号,不靠
# HTTP 猜)。三态:healthy→REDACT、down→强制 BLOCK(l3_unavailable)、restored→REDACT。
# (keep 旧 fail-open 的『明文外发』量化须 echo 上游,归 §9 实验 D fake_upstream 做。)
set +e
cd /home/ec2-user/kiro-dlp/gateway
M=/metrics/dlp_gateway_metrics.jsonl
KEY=$(sudo docker inspect litellm --format '{{range .Config.Env}}{{println .}}{{end}}' | grep '^LITELLM_MASTER_KEY=' | cut -d= -f2-)

probe () { # $1=label
  sudo docker exec litellm sh -c ": > $M"   # 清指标,便于取本次那条
  KEY="$KEY" python3 - "$1" <<'PY'
import json,os,sys,urllib.request,urllib.error
label=sys.argv[1]; key=os.environ["KEY"]; base="http://localhost:4000/v1"
vec="charge this card 4539578763621486 today"
body={"model":"llama-3.1-8b","messages":[{"role":"user","content":vec}],"max_tokens":16}
req=urllib.request.Request(base+"/chat/completions",data=json.dumps(body).encode(),
    headers={"Content-Type":"application/json","Authorization":"Bearer "+key},method="POST")
try:
    with urllib.request.urlopen(req,timeout=60) as r: st=r.status
except urllib.error.HTTPError as e: st=e.code
print("  [%s] HTTP=%s"%(label,st),end=" ")
PY
  # 读本次 pre_call 权威裁决
  sudo docker exec litellm sh -c "grep '\"kind\": \"pre_call\"' $M | tail -1" | python3 -c "import sys,json
x=json.loads(sys.stdin.read() or '{}')
print('verdict=%s top=%s forced=%s'%(x.get('verdict'),x.get('top_layer'),x.get('forced_block','-')))"
}

echo "=== 1) Presidio 健康 → 期望 verdict=redact top=L3 ==="
sudo docker ps --format '{{.Names}} {{.Status}}' | grep presidio
probe "presidio-up"

echo "=== 2) 停 presidio(默认 fail-closed)→ 期望 HTTP=400 verdict=block forced=l3_unavailable ==="
sudo docker stop presidio-analyzer >/dev/null; sleep 2; echo "presidio: 已停"
probe "down-failclosed"

echo "=== 3) 恢复 presidio → 期望 verdict=redact top=L3(自愈)==="
sudo docker start presidio-analyzer >/dev/null
for i in $(seq 1 40); do [ "$(sudo docker inspect presidio-analyzer --format '{{.State.Health.Status}}' 2>/dev/null)" = healthy ] && { echo "presidio healthy ~${i}x3s"; break; }; sleep 3; done
probe "restored"
echo "=== 专项完成(裁决以 metrics verdict 为准)==="
