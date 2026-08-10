#!/bin/bash
# 阶段6 性能测试一键 runner(在 kiro-dlp 实例上执行,03 文档 §9.7)。
#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
# 前置(由 sync 脚本铺到实例):
#   /home/ec2-user/kiro-dlp/{docker,gateway,engine,testing/perf}
#   k6 已装(/usr/local/bin/k6);litellm/presidio 容器在跑。
# 本脚本:①起 host 假上游 ②切 perf 版 litellm 配置 ③冒烟三态 ④按 EXP 跑 k6 ⑤归档。
#
# 用法:
#   bash run_perf.sh smoke                 # 只冒烟(假上游 + 三态)
#   bash run_perf.sh A|B|C|D  [k6 env...]  # 跑指定实验
#   bash run_perf.sh all                   # 顺序跑 B→A→C→D
# 需先 export LITELLM_MASTER_KEY(与在跑的 litellm 一致);KEY 传给 k6 做鉴权。
set -uo pipefail

ROOT=/home/ec2-user/kiro-dlp
PERF="$ROOT/testing/perf"
DOCKER="$ROOT/docker"
DATE=$(date +%F)
OUT="$PERF/results-$DATE"
mkdir -p "$OUT"
: "${LITELLM_MASTER_KEY:?请先 export LITELLM_MASTER_KEY(与在跑 litellm 一致)}"
KEY="$LITELLM_MASTER_KEY"
BASE_URL="${BASE_URL:-http://localhost:4000}"

log(){ echo "[$(date +%T)] $*"; }

start_fake_upstream(){
  if curl -sf http://127.0.0.1:18080/health >/dev/null 2>&1; then
    log "假上游已在跑"; return; fi
  log "起假上游 fake_upstream.py :18080(绑 0.0.0.0)"
  # 必须绑 0.0.0.0:litellm 容器经 docker 网桥 host.docker.internal→172.17.0.1 回连宿主,
  # 仅绑 127.0.0.1 会拒绝网桥 IP → PASS/REDACT 打不到假上游 → litellm 500(非泄漏,是连不上)。
  # 端口 18080 不在实例 SG 任何 ingress 规则里,故绑 0.0.0.0 不产生 VPC/公网暴露;假上游是
  # 纯本机 echo 服务,内容不出实例。宿主 127.0.0.1 健康检查仍可用。
  FAKE_UPSTREAM_BIND=0.0.0.0 nohup python3 "$PERF/fake_upstream.py" >"$OUT/fake_upstream.log" 2>&1 &
  echo $! > "$PERF/.fake_upstream.pid"
  for i in $(seq 1 20); do
    curl -sf http://127.0.0.1:18080/health >/dev/null 2>&1 && { log "假上游就绪"; return; }
    sleep 0.5
  done
  log "假上游未就绪,看 $OUT/fake_upstream.log"; exit 1
}

switch_perf_config(){
  log "切 litellm 到 perf 配置(加 echo-fast 假上游 + host.docker.internal)"
  cd "$DOCKER" || exit 1
  docker compose -f docker-compose.yml -f docker-compose.gateway.yml \
    -f "$PERF/docker-compose.perf.yml" up -d litellm
  for i in $(seq 1 30); do
    curl -sf "$BASE_URL/health/readiness" >/dev/null 2>&1 && { log "litellm(perf)就绪"; sleep 2; return; }
    sleep 1
  done
  log "litellm 未就绪"; docker logs --tail 40 litellm; exit 1
}

smoke(){
  log "冒烟:经假上游验 PASS/REDACT/BLOCK 三态"
  # PASS
  P=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/v1/chat/completions" \
      -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
      -d '{"model":"echo-fast","messages":[{"role":"user","content":"你好,今天天气不错"}],"max_tokens":16}')
  log "  PASS 期望200 → $P"
  # REDACT(邮箱)—— 看 echo 里明文是否消失
  R=$(curl -s -X POST "$BASE_URL/v1/chat/completions" \
      -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
      -d '{"model":"echo-fast","messages":[{"role":"user","content":"reach me at john.doe@gmail.com please"}],"max_tokens":16}')
  if echo "$R" | grep -q 'john.doe@gmail.com'; then log "  ★REDACT 冒烟:明文仍在(异常!)"; else log "  REDACT 冒烟:明文已脱敏 ✓"; fi
  # BLOCK(AWS key)
  B=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/v1/chat/completions" \
      -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
      -d '{"model":"echo-fast","messages":[{"role":"user","content":"deploy key AKIA1234567890ABCDEF to prod"}],"max_tokens":16}')
  log "  BLOCK 期望400 → $B"
}

snapshot(){  # 压测中途快照(§9.5):docker stats + mpstat
  local tag="$1"
  docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}' \
    > "$OUT/stats_${tag}.txt" 2>&1
  command -v mpstat >/dev/null 2>&1 && mpstat -P ALL 1 1 > "$OUT/mpstat_${tag}.txt" 2>&1 || true
}

run_exp(){
  local exp="$1"; shift
  log "===== 实验 $exp 开始 ====="
  ( sleep 5; snapshot "$exp" ) &   # 压测中段抓一次快照
  cd "$PERF" || exit 1
  BASE_URL="$BASE_URL" MODEL=echo-fast KEY="$KEY" EXP="$exp" \
    k6 run "$@" dlp_perf.js 2>&1 | tee "$OUT/k6_${exp}.txt"
  [ -f "$PERF/summary_${exp}.json" ] && mv "$PERF/summary_${exp}.json" "$OUT/"
  log "===== 实验 $exp 完成,归档 $OUT ====="
}

case "${1:-smoke}" in
  smoke) start_fake_upstream; switch_perf_config; smoke ;;
  A|B|C|D) EXP1="$1"; shift; start_fake_upstream; switch_perf_config; smoke; run_exp "$EXP1" "$@" ;;
  all)
    start_fake_upstream; switch_perf_config; smoke
    run_exp B --vus-max 400 || run_exp B
    run_exp A
    run_exp C
    run_exp D
    ;;
  *) echo "用法: $0 smoke|A|B|C|D|all"; exit 2 ;;
esac
log "全部完成。结果在 $OUT/"
ls -la "$OUT/"
