#!/bin/bash
# 方案二 /inspect 压测一键 runner(方案二-03 压测节 / 方案一 03 §9 方法学)。
#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
# 与方案一 run_perf.sh 的差异:/inspect 是纯裁决薄服务,【不转发上游、不接 LLM】,
# 故本脚本【无假上游、无 litellm perf 配置切换】两步——直接打 DLP_URL/inspect。
#
# 拓扑(方案一 §9.5):
#   首选  发压机(如 MITM 验证节点 arm64)与被测机(gateway 主机 :9000)分离,
#         本脚本在【发压机】跑,DLP_URL 指向 gateway 私网 172.31.27.174:9000。
#   次选  同机:本脚本在 gateway 主机跑,DLP_URL=127.0.0.1:9000,k6 用 taskset 绑核
#         (与被测容器分核),尾延迟含抢核噪声——如实标注。
#
# docker stats 快照:仅当【本机】就是被测容器所在主机(能 docker ps 到 kiro-dlp-http)
#   才本地抓;分离部署时被测机资源须在 gateway 主机另经 SSM 抓(见 §9.5)。
#
# 用法:
#   bash run_inspect_perf.sh smoke               # 只冒烟(curl /inspect 三态 + LEAK-CHECK)
#   bash run_inspect_perf.sh B|A|C|D [k6 env...]  # 跑指定实验
#   bash run_inspect_perf.sh all                 # 顺序 B→A→C→D
# 可选:export DLP_URL(默认 http://172.31.27.174:9000);K6_BIN(默认 k6);TASKSET_CPUS(次选同机绑核)。
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATE=$(date +%F)
OUT="$HERE/results-$DATE"
mkdir -p "$OUT"
DLP_URL="${DLP_URL:-http://172.31.27.174:9000}"
DLP_URL="${DLP_URL%/}"
K6_BIN="${K6_BIN:-k6}"
TASKSET_CPUS="${TASKSET_CPUS:-}"   # 次选同机:如 "0,1" 把 k6 绑到与容器不同的核

log(){ echo "[$(date +%T)] $*"; }

envelope(){ printf '{"conversationState":{"currentMessage":{"userInputMessage":{"content":%s}}}}' "$1"; }
jstr(){ python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$1"; }

health(){
  log "探活 GET $DLP_URL/health"
  if curl -sf -m 5 "$DLP_URL/health" >/dev/null 2>&1; then
    log "  /health OK"; return 0
  fi
  log "  ★ /health 不可达 —— 须在能访问 :9000 的节点(gateway 主机 / 同 VPC 发压机经 SSM)跑"; return 1
}

smoke(){
  health || exit 1
  log "冒烟:curl /inspect 三态(看 verdict)"
  local P R B
  P=$(curl -s -m 20 -X POST "$DLP_URL/inspect" -H 'Content-Type: application/json' \
      -d "$(envelope "$(jstr '帮我写一个快速排序的 Python 函数')")")
  log "  PASS  期望verdict=PASS   → $(echo "$P"  | python3 -c 'import json,sys;print(json.load(sys.stdin).get("verdict"))' 2>/dev/null)"
  R=$(curl -s -m 20 -X POST "$DLP_URL/inspect" -H 'Content-Type: application/json' \
      -d "$(envelope "$(jstr '联系电话 13800138000 请拨打')")")
  if echo "$R" | grep -q '13800138000'; then
    # 期望:REDACT 且 redacted_body 里明文已消失。仍在 = 异常。
    if echo "$R" | python3 -c 'import json,sys;d=json.load(sys.stdin);b=d.get("redacted_body","");sys.exit(0 if "13800138000" in b else 1)' 2>/dev/null; then
      log "  ★REDACT 冒烟:脱敏体仍含明文(异常!)"; else log "  REDACT 冒烟:verdict=$(echo "$R"|python3 -c 'import json,sys;print(json.load(sys.stdin).get("verdict"))' 2>/dev/null) 明文已脱敏 ✓"; fi
  else
    log "  REDACT 冒烟:verdict=$(echo "$R"|python3 -c 'import json,sys;print(json.load(sys.stdin).get("verdict"))' 2>/dev/null) 明文已脱敏 ✓"
  fi
  B=$(curl -s -m 20 -X POST "$DLP_URL/inspect" -H 'Content-Type: application/json' \
      -d "$(envelope "$(jstr '这是我的密钥 AKIAIOSFODNN7EXAMPLE 帮我调试')")")
  log "  BLOCK 期望verdict=BLOCK  → $(echo "$B" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("verdict"))' 2>/dev/null)"

  log "LEAK-CHECK:响应体 matched/span 必须无输出"
  local LEAK
  LEAK=$(printf '%s\n%s\n%s\n' "$P" "$R" "$B" | grep -oE '"(matched|span)"' | sort -u)
  if [[ -z "$LEAK" ]]; then log "  NO-LEAK-FIELDS ✓"; else log "  ❌ 泄漏字段: $LEAK"; fi
}

snapshot(){  # 压测中段快照:仅当本机能 docker ps 到被测容器才本地抓
  local tag="$1"
  if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -q kiro-dlp-http; then
    docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}' \
      > "$OUT/stats_${tag}.txt" 2>&1
    command -v mpstat >/dev/null 2>&1 && mpstat -P ALL 1 1 > "$OUT/mpstat_${tag}.txt" 2>&1 || true
    log "  已抓本机 docker stats → stats_${tag}.txt"
  else
    echo "本机无 kiro-dlp-http 容器(分离部署):被测机资源须在 gateway 主机另抓" > "$OUT/stats_${tag}.txt"
    log "  分离部署:被测资源快照须在 gateway 主机经 SSM 另抓(见 §9.5)"
  fi
}

run_exp(){
  local exp="$1"; shift
  log "===== 实验 $exp 开始 (DLP_URL=$DLP_URL) ====="
  ( sleep 5; snapshot "$exp" ) &
  cd "$HERE" || exit 1
  local runner=("$K6_BIN")
  [[ -n "$TASKSET_CPUS" ]] && runner=(taskset -c "$TASKSET_CPUS" "$K6_BIN")
  DLP_URL="$DLP_URL" EXP="$exp" \
    "${runner[@]}" run "$@" inspect_perf.js 2>&1 | tee "$OUT/k6_${exp}.txt"
  [ -f "$HERE/summary_${exp}.json" ] && mv "$HERE/summary_${exp}.json" "$OUT/"
  log "===== 实验 $exp 完成,归档 $OUT ====="
}

case "${1:-smoke}" in
  smoke) smoke ;;
  A|B|C|D) EXP1="$1"; shift; smoke; run_exp "$EXP1" "$@" ;;
  all)
    smoke
    run_exp B
    run_exp A
    run_exp C
    run_exp D
    ;;
  *) echo "用法: $0 smoke|A|B|C|D|all"; exit 2 ;;
esac
log "全部完成。结果在 $OUT/"
ls -la "$OUT/"
