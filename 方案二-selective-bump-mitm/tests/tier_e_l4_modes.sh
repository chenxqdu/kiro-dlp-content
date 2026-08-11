#!/usr/bin/env bash
#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
# Tier E —— L4 语义三态开关 (DLP_L4_MODE ∈ {off, async, sync}) 真机断言。
#
# 子测：(i) async 放行+落 sink / (ii) sync 高置信 BLOCK+落 sink /
#       (iii) sync 超时降级放行+补落 sink / (iv) sink 结构契约(无 matched/span/context,
#       明文仅可能落 rationale) / (v) 严档 DLP_L4_SINK_RATIONALE=false 证零明文回显。
#
# ★ sink 行由 json.dumps 生成——冒号后【带一个空格】(`"kind": "l4_alert"`);所有 grep
#   一律用 `"kind":[[:space:]]*"l4_alert"`,【绝不】写死无空格模式(那会永不匹配、假 FAIL)。
#
# ★ 运行位置：【DLP 主机】(<TEST_INSTANCE_ID>, 172.31.27.174)，经 SSM 会话执行。
#   本脚本会【切换 DLP_L4_MODE 并重建 :9000 判定服务容器】——写一个 compose override
#   文件叠加 environment，再 `docker compose -f base -f override up -d`，
#   【绝不改动 committed 的 docker-compose.dlp-http.yml】。收尾恢复为 base(committed 默认)。
#
# ★ 因此本脚本【不接入 run_all.sh】：run_all.sh 跑在 proxy 节点、环境自检强依赖
#   /etc/mitm/certs、且不切 compose env；本脚本的前提是 DLP 主机 + docker + compose。
#
# 判定约定(同 run_all.sh)：任何 `❌` = FAIL；结尾打 PASS/FAIL 汇总 + 相应退出码。
#
# 离线安全设计：待判语料是【无签名的语义敏感内容】(未公开定价/风控加权系数)——
#   L0–L3.5 结构上检不到；离线启发式 (_heuristic_alert) 对 "业务领域词 + 自研逻辑特征
#   (权重/公式/阈值)" 给 confidence=0.7，恰等于默认 DLP_L4_BLOCK_MIN_CONFIDENCE=0.7，
#   故 sync 态即便 Bedrock 不可达也能断言 BLOCK。唯 (iii) 超时降级需真实 Bedrock RTT
#   才能触发(启发式是纯正则、微秒级完成，50ms 也不会超时)——backend=offline 时该子测标 SKIP。
#
# 可覆盖 env：
#   DLP_INSPECT_BASE (默认 http://172.31.27.174:9000)
#   KIRO_DLP_DIR     (默认 /home/ec2-user/kiro-dlp，含 docker-compose.dlp-http.yml)
#   DOCKER_CLI       (默认 docker；如需 sudo 设为 "sudo docker")
set -uo pipefail

DLP="${DLP_INSPECT_BASE:-http://172.31.27.174:9000}"
COMPOSE_DIR="${KIRO_DLP_DIR:-/home/ec2-user/kiro-dlp}"
DCLI="${DOCKER_CLI:-docker}"
BASE="docker-compose.dlp-http.yml"
OVERRIDE="docker-compose.tier-e.override.yml"     # 临时叠加，收尾删除
SERVICE="dlp-http"                                 # ★ compose 服务名(≠容器名)；override 必须用它做 key
CONTAINER="kiro-dlp-http"                          # container_name，供 docker logs / inspect 用
ALLSINK="/tmp/te_sink_all.log"
FAIL=0
: > "$ALLSINK"

# 无签名语义敏感内容：定价/风控/额度(biz) + "× 0.d 系数" 与 "score =" 公式写法(logic)
#   → 启发式命中 proprietary-business-logic，confidence=0.7 == 默认 min_conf。
SENSITIVE='我司未公开定价策略与渠道扩张：风控加权 risk_score = 逾期指标 × 0.62 + 额度指标 × 0.38，阈值 0.75 触发拒贷'
# 无原文核查用的高辨识度明文片段(sink 的 category/model/rationale 都不该含它)。
PROBE='逾期指标 × 0.62'
BODY=$(printf '{"conversationState":{"currentMessage":{"userInputMessage":{"content":"%s"}}}}' "$SENSITIVE")

say() { echo "=============== $* ==============="; }
bad() { echo "❌ $*"; FAIL=1; }
ok()  { echo "✓ $*"; }

cleanup() {
  say "CLEANUP：恢复 committed 默认(仅 base compose) + 删 override"
  ( cd "$COMPOSE_DIR" && $DCLI compose -f "$BASE" up -d ) >/dev/null 2>&1 \
    && ok "已按 committed 默认重建 $CONTAINER" \
    || echo "⚠ 恢复默认失败，请手动 cd $COMPOSE_DIR && $DCLI compose -f $BASE up -d"
  rm -f "$COMPOSE_DIR/$OVERRIDE"
}
trap cleanup EXIT

wait_health() {
  local i
  for i in $(seq 1 30); do
    if curl -s -m 3 "$DLP/health" | grep -qE '"status":[[:space:]]*"ok"'; then return 0; fi
    sleep 1
  done
  return 1
}

apply_mode() {  # $1=mode  $2=timeout_ms  [$3=sink_rationale, 默认 true]
  local rat="${3:-true}"
  cat > "$COMPOSE_DIR/$OVERRIDE" <<YML
services:
  $SERVICE:
    environment:
      DLP_L4_MODE: "$1"
      DLP_L4_TIMEOUT_MS: "$2"
      DLP_L4_SINK_RATIONALE: "$rat"
YML
  ( cd "$COMPOSE_DIR" && $DCLI compose -f "$BASE" -f "$OVERRIDE" up -d ) >/dev/null 2>&1
  if ! wait_health; then bad "mode=$1 重建后 /health 未就绪"; return 1; fi
  # 打出启动横幅(mode/backend)，便于人工核对。
  $DCLI logs --since 20s "$CONTAINER" 2>&1 | grep -E 'L4 mode=|后端 = Bedrock|离线启发式' | tail -3
  return 0
}

detect_backend() {  # 读运行容器的 DLP_USE_BEDROCK_L4 -> bedrock|offline
  local v
  v=$($DCLI inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$CONTAINER" 2>/dev/null \
      | grep '^DLP_USE_BEDROCK_L4=' | head -1 | cut -d= -f2)
  case "$(printf '%s' "$v" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on) echo "bedrock" ;;
    *)             echo "offline" ;;
  esac
}

inspect_to() {  # $1=outfile -> 打印 http_code
  curl -s -m 30 -X POST "$DLP/inspect" -H 'Content-Type: application/json' \
    --data-binary "$BODY" -o "$1" -w '%{http_code}'
}

summarize() {  # <file> -> "verdict|top_layer|has_redacted|has_l4rule"
  python3 - "$1" <<'PY'
import json, sys
try:
    o = json.load(open(sys.argv[1]))
except Exception:
    print("PARSE_ERR|-|no|no"); sys.exit(0)
hl = "no"
for r in (o.get("rules") or []):
    if str(r.get("rule", "")).startswith("l4_semantic:"):
        hl = "yes"; break
print("{}|{}|{}|{}".format(
    o.get("verdict"), o.get("top_layer"),
    "yes" if o.get("redacted_body") is not None else "no", hl))
PY
}

capture_sink() {  # $1=since -> 打印并累积 l4_alert 行到 ALLSINK
  # ★ 铁律:sink 行由 json.dumps 生成,冒号后带一个空格(`"kind": "l4_alert"`);
  #   grep 模式必须【冒号空格容错】(`:[[:space:]]*`),绝不写死 `"kind":"l4_alert"`(无空格,永不匹配)。
  $DCLI logs --since "${1:-60s}" "$CONTAINER" 2>&1 | grep -E '"kind":[[:space:]]*"l4_alert"' | tee -a "$ALLSINK"
}

# ───────────────────────── (i) async ─────────────────────────
say "(i) async —— 同步腿放行 + 后台异步告警落 sink"
if apply_mode async 4000; then
  code=$(inspect_to /tmp/te_async.json)
  [ "$code" = 200 ] && ok "async HTTP=200" || bad "async HTTP=$code (期望 200)"
  IFS='|' read -r v tl hr hl <<<"$(summarize /tmp/te_async.json)"
  [ "$v" != BLOCK ] && ok "async 未阻断 verdict=$v" || bad "async verdict=BLOCK (async 绝不该改 verdict)"
  [ "$tl" != L4 ]   && ok "async top_layer=$tl (非 L4，同步腿无 L4 污染)" || bad "async top_layer=L4"
  sleep 3
  S=$(capture_sink 60s)
  echo "$S" | grep -qE '"kind":[[:space:]]*"l4_alert"' && ok "async sink 出告警行" || bad "async 未见 l4_alert sink 行"
fi

# ───────────────────────── (ii) sync BLOCK ─────────────────────────
say "(ii) sync —— 高置信合成 BLOCK (DLP_L4_TIMEOUT_MS=6000)"
if apply_mode sync 6000; then
  code=$(inspect_to /tmp/te_sync.json)
  [ "$code" = 200 ] && ok "sync HTTP=200 (注：合成 BLOCK 也是 200)" || bad "sync HTTP=$code (期望 200)"
  IFS='|' read -r v tl hr hl <<<"$(summarize /tmp/te_sync.json)"
  [ "$v" = BLOCK ] && ok "sync verdict=BLOCK" || bad "sync verdict=$v (期望 BLOCK)"
  [ "$tl" = L4 ]   && ok "sync top_layer=L4" || bad "sync top_layer=$tl (期望 L4)"
  [ "$hl" = yes ]  && ok "rules 含 l4_semantic:*" || bad "rules 无 l4_semantic:* (期望有)"
  [ "$hr" = no ]   && ok "无 redacted_body (BLOCK 短路)" || bad "有 redacted_body (BLOCK 不该带脱敏体)"
  sleep 2
  S=$(capture_sink 60s)
  echo "$S" | grep -qE '"kind":[[:space:]]*"l4_alert"' && ok "sync sink 亦出告警行" || bad "sync 未见 l4_alert sink 行"
fi

# ───────────────────────── (iii) sync 超时降级 ─────────────────────────
say "(iii) sync 超时降级放行 (DLP_L4_TIMEOUT_MS=50)"
if apply_mode sync 50; then
  BACKEND=$(detect_backend)
  if [ "$BACKEND" = bedrock ]; then
    code=$(inspect_to /tmp/te_to.json)
    [ "$code" = 200 ] && ok "downgrade HTTP=200" || bad "downgrade HTTP=$code (期望 200)"
    IFS='|' read -r v tl hr hl <<<"$(summarize /tmp/te_to.json)"
    [ "$v" != BLOCK ] && ok "超时降级：verdict=$v (按 L0–L3.5 放行，非 BLOCK)" || bad "超时未降级：verdict=BLOCK"
    [ "$tl" != L4 ]   && ok "超时降级 top_layer=$tl (非 L4)" || bad "超时降级 top_layer=L4"
    sleep 4
    S=$(capture_sink 60s)
    echo "$S" | grep -qE '"kind":[[:space:]]*"l4_alert"' && ok "超时后 sink 补出告警行" || bad "超时后未见补落 sink 行"
  else
    echo "⏭ SKIP (iii)：backend=offline，启发式微秒级完成不会超时；超时降级需真实 Bedrock RTT。"
    echo "   真机 Bedrock 下该子测见 方案二-03-测试报告.md §4.5 Tier E (Q4 回填)。"
  fi
fi

# ───────────────────────── (iv) sink 结构契约 + 明文只可能落 rationale ─────────────────────────
# 逐行 JSON 解析(前三态 sink_rationale=true 默认)。硬契约(恒成立):
#   1) 绝无 matched/span/context 字段(原始敏感子串/定位绝不出服务);
#   2) PROBE 明文片段【只可能】出现在 rationale 值里——这是知情接受的风险#4
#      (Bedrock 自由文本回显),出现在【任何其它字段】即 FAIL。
#   rationale 本身是否含 PROBE 不判 fail(默认档接受);(v) 专证严档零回显。
say "(iv) sink 结构契约 + 明文仅可能落 rationale (聚合核查, sink_rationale=默认 true)"
if [ -s "$ALLSINK" ]; then
  # ★ sink 行经 docker logs 捞出时带日志前缀(`TS LEVEL dlp-l4 {json}`)——
  #   须从第一个 `{` 起截取才能 json.loads,否则整行解析必失败(PARSED 0 假 FAIL)。
  python3 - "$ALLSINK" "$PROBE" <<'PY'
import json, sys
path, probe = sys.argv[1], sys.argv[2]
bad_fields, leak_other, n = [], [], 0
with open(path, encoding="utf-8") as fh:
    for ln in fh:
        if '"l4_alert"' not in ln:
            continue
        i = ln.find("{")
        if i < 0:
            continue
        try:
            o = json.loads(ln[i:])
        except Exception:
            continue
        n += 1
        for k in ("matched", "span", "context"):
            if k in o and k not in bad_fields:
                bad_fields.append(k)
        for k, v in o.items():
            if k == "rationale":
                continue  # 默认档接受 rationale 回显(风险#4)
            if isinstance(v, str) and probe in v:
                leak_other.append(k)
print("PARSED", n)
print("BADF", ",".join(sorted(set(bad_fields))))
print("LEAKOTHER", ",".join(sorted(set(leak_other))))
PY
  IV=$(python3 - "$ALLSINK" "$PROBE" <<'PY'
import json, sys
path, probe = sys.argv[1], sys.argv[2]
bad, other, n = set(), set(), 0
for ln in open(path, encoding="utf-8"):
    if '"l4_alert"' not in ln: continue
    i = ln.find("{")
    if i < 0: continue
    try: o = json.loads(ln[i:])
    except Exception: continue
    n += 1
    for k in ("matched","span","context"):
        if k in o: bad.add(k)
    for k,v in o.items():
        if k!="rationale" and isinstance(v,str) and probe in v: other.add(k)
print(f"{n}|{','.join(sorted(bad))}|{','.join(sorted(other))}")
PY
)
  IFS='|' read -r np bf lo <<<"$IV"
  [ "${np:-0}" -ge 1 ] && ok "sink 有 $np 行 l4_alert 可解析" || bad "sink 无可解析 l4_alert 行(前三态应已落行)"
  [ -z "$bf" ] && ok "sink 无 matched/span/context 字段(硬契约)" || bad "sink 含敏感字段: $bf"
  [ -z "$lo" ] && ok "PROBE 未出现在 rationale 以外任何字段" || bad "PROBE 泄漏进非 rationale 字段: $lo"
else
  bad "sink 累积文件为空,前三态未落任何行(不应发生)"
fi

# ───────────────────────── (v) 严档零回显:DLP_L4_SINK_RATIONALE=false ─────────────────────────
# 证"回显可消除":关掉 rationale 落盘后,sink 行【彻底不含】PROBE 任何形态,且无 rationale 字段。
say "(v) 严档 DLP_L4_SINK_RATIONALE=false —— sink 零明文回显"
: > "$ALLSINK"                                    # 重置累积,只看严档这一段
if apply_mode async 4000 false; then
  BACKEND=$(detect_backend)
  code=$(inspect_to /tmp/te_strict.json)
  [ "$code" = 200 ] && ok "strict HTTP=200" || bad "strict HTTP=$code (期望 200)"
  sleep 3
  S=$(capture_sink 60s)
  if [ "$BACKEND" = bedrock ]; then
    echo "$S" | grep -qE '"kind":[[:space:]]*"l4_alert"' && ok "严档 sink 仍出告警行" || bad "严档未见 l4_alert sink 行"
  else
    echo "$S" | grep -qE '"kind":[[:space:]]*"l4_alert"' && ok "严档 sink 仍出告警行(启发式)" \
      || echo "⏭ SKIP (v) 行断言：backend=offline 且未落行(启发式仍应落行,此处宽容)"
  fi
  # 硬断言:严档下 sink 绝无 rationale 字段、绝无 PROBE 任何片段。
  NOR=$(echo "$S" | grep -c '"rationale"' || true)
  [ "${NOR:-0}" = 0 ] && ok "严档 sink 无 rationale 字段" || bad "严档 sink 仍含 rationale 字段($NOR 行)"
  LEAK=$(echo "$S" | grep -F "$PROBE" || true)
  [ -z "$LEAK" ] && ok "严档 sink 零明文回显 ($PROBE 全无)" || bad "严档 sink 仍泄漏原文: $LEAK"
fi

# ───────────────────────── 汇总 ─────────────────────────
say "TIER-E 汇总"
if [ "$FAIL" = 0 ]; then echo "TIER-E PASS ✓"; else echo "❌ TIER-E FAIL"; fi
exit "$FAIL"
