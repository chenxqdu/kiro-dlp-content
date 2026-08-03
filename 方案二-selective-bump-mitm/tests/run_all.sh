#!/usr/bin/env bash
#############################################
# 方案二 · 一键测试运行器（在【验证节点 EC2】上经 SSM 执行）
#
# 串联全部测试层，逐层判定 PASS/FAIL 并在末尾汇总：
#   0  预检/bump/透传  : §2 bump 域严格校验(Verify 0 + issuer=我方中间CA)
#                        §3 透传域红线(issuer=Amazon，绝不为我方CA)         —— 本脚本内联
#   a  tier_a_smoke    : §4 Tier A 直连 DLP /inspect 三态 + 脱敏字段不外泄
#   b  tier_b_wire     : §4 Tier B wire-byte 铁证(PASS/REDACT/BLOCK 发往上游的字节)
#   c  tier_c_real     : §4 Tier C 真实上游交叉核对(PASS 到 AWS / BLOCK 我方短路)
#   f  tier_fail_modes : §5 fail 模式四子测(不可达吃策略 / HTTP503 恒 closed)
#
# 用法（在 proxy 本机 SSM 会话内）：
#   ./run_all.sh            # 跑全部(0 a b c f)
#   ./run_all.sh 0 a b      # 只跑指定层(空格分隔)
#   ./run_all.sh --list     # 列出层
#
# 判定：某层输出含 ❌ 或 FATAL 视为 FAIL；否则 PASS。日志落 /tmp/kiro-mitm-tests/。
#
# ★ 全程只打 127.0.0.1（loopback，无公网 443）；生产 SNI 透传节点绝不涉及。
# ★ 期望结论见 TEST-PLAN.md（oracle）；实测结论见 方案二-03-测试报告.md。
#############################################
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS=/etc/mitm/certs
BUMP=runtime.us-east-1.kiro.dev
PASSTHRU=codewhisperer.us-east-1.amazonaws.com
LOGDIR=/tmp/kiro-mitm-tests
mkdir -p "$LOGDIR"

ALL_TIERS=(0 a b c f)
declare -A SCRIPT_OF=(
  [a]="tier_a_smoke.sh"
  [b]="tier_b_wire.sh"
  [c]="tier_c_real_upstream.sh"
  [f]="tier_fail_modes.sh"
)
declare -A NAME_OF=(
  [0]="§2/§3 预检: bump 严格校验 + 透传红线"
  [a]="§4 Tier A: DLP /inspect 三态 + 无泄漏"
  [b]="§4 Tier B: wire-byte 铁证"
  [c]="§4 Tier C: 真实上游交叉核对"
  [f]="§5 fail 模式四子测"
)

if [[ "${1:-}" == "--list" ]]; then
  for t in "${ALL_TIERS[@]}"; do printf "  %s  %s\n" "$t" "${NAME_OF[$t]}"; done
  exit 0
fi

# 选层：无参 = 全部
if [[ $# -gt 0 ]]; then TIERS=("$@"); else TIERS=("${ALL_TIERS[@]}"); fi

#############################################
# 环境自检：确保确实在验证节点(proxy)本机
#############################################
echo "==================== 环境自检 ===================="
FATAL_ENV=0
if [[ ! -f "$CERTS/root.crt" ]]; then
  echo "❌ 未找到 $CERTS/root.crt —— 本脚本必须在【验证节点 proxy EC2】上运行(经 SSM)"; FATAL_ENV=1
fi
if ! command -v openssl >/dev/null 2>&1; then echo "❌ 缺 openssl"; FATAL_ENV=1; fi
PROD_MITM="$(sudo systemctl is-active kiro-mitm 2>/dev/null || true)"
PROD_NGINX="$(sudo systemctl is-active nginx 2>/dev/null || true)"
echo "  kiro-mitm=$PROD_MITM  nginx=$PROD_NGINX  certs=$( [[ -f $CERTS/root.crt ]] && echo ok || echo MISSING )"
if [[ "$FATAL_ENV" == "1" ]]; then echo "环境不满足，退出。"; exit 2; fi
echo

#############################################
# 逐层执行
#############################################
declare -A RESULT
run_and_grade () {  # $1=tier key  $2=cmd(数组式，用字符串传)
  local t="$1"; shift
  local log="$LOGDIR/tier_${t}.log"
  echo "########################################################"
  echo "#  层 $t —— ${NAME_OF[$t]}"
  echo "#  日志: $log"
  echo "########################################################"
  # 用 tee 同时落盘+回显；scripts 自身 set -uo(非 -e)，不会因单条失败中断
  ( "$@" ) 2>&1 | tee "$log"
  # 判定：出现 ❌ / FATAL 即 FAIL
  if grep -qE '❌|FATAL' "$log"; then
    RESULT[$t]="FAIL"
    echo ">>> 层 $t 判定: ❌ FAIL"
  else
    RESULT[$t]="PASS"
    echo ">>> 层 $t 判定: ✅ PASS"
  fi
  echo
}

# ---- 层 0：内联预检(bump 严格校验 + 透传红线) ----
tier0_inline () {
  echo "===== §2 bump 域严格校验: $BUMP ====="
  # curl 严格(TLSv1.3)：期望 SSL certificate verify ok + HTTP 应答
  echo "--- curl 严格校验 ---"
  curl -sv --cacert "$CERTS/root.crt" --resolve "${BUMP}:443:127.0.0.1" \
       "https://${BUMP}:443/" -m 15 2>&1 | grep -iE 'SSL certificate verify|subject:|issuer:|HTTP/' | head -8
  echo "--- openssl -verify_return_error ---"
  local out; out="$(echo | openssl s_client -connect 127.0.0.1:443 -servername "$BUMP" \
       -CAfile "$CERTS/root.crt" -verify_return_error 2>&1)"
  echo "$out" | grep -E 'Verify return code|issuer=' | head -4
  if echo "$out" | grep -q 'Verify return code: 0 (ok)' \
     && echo "$out" | grep -qi 'Issuing CA'; then
    echo "  bump: Verify 0 + issuer=我方中间 CA ✓"
  else
    echo "  bump: ❌ 严格校验未通过或 issuer 非我方中间 CA(疑似证书链/NC 问题)"
  fi
  echo
  echo "===== §3 透传域红线: $PASSTHRU (issuer 绝不能是我方 CA) ====="
  local pt; pt="$(echo | openssl s_client -connect 127.0.0.1:443 -servername "$PASSTHRU" 2>&1)"
  echo "$pt" | grep -E 'issuer=' | head -1
  if echo "$pt" | grep -qi 'Amazon' && ! echo "$pt" | grep -qi 'Issuing CA\|Kiro-DLP'; then
    echo "  透传红线: issuer=Amazon 原生，未被我方 CA 触碰 ✓"
  else
    echo "  透传红线: ❌ 透传域 issuer 异常(若含我方 CA=误 bump，立即停止回滚!)"
  fi
}

for t in "${TIERS[@]}"; do
  case "$t" in
    0) run_and_grade 0 tier0_inline ;;
    a|b|c|f)
      s="${SCRIPT_OF[$t]}"
      if [[ ! -f "$SCRIPT_DIR/$s" ]]; then
        echo "❌ 缺脚本 $SCRIPT_DIR/$s，跳过层 $t"; RESULT[$t]="MISSING"; echo; continue
      fi
      chmod +x "$SCRIPT_DIR/$s" 2>/dev/null || true
      run_and_grade "$t" bash "$SCRIPT_DIR/$s"
      ;;
    *) echo "未知层 '$t'（可选: ${ALL_TIERS[*]}），跳过"; echo ;;
  esac
done

#############################################
# 汇总
#############################################
echo "========================================================"
echo "                    测试汇总"
echo "========================================================"
FAILED=0
for t in "${TIERS[@]}"; do
  r="${RESULT[$t]:-SKIP}"
  case "$r" in
    PASS)    icon="✅" ;;
    FAIL)    icon="❌"; FAILED=1 ;;
    MISSING) icon="⚠️ "; FAILED=1 ;;
    *)       icon="·" ;;
  esac
  printf "  %s  层 %s  %-40s %s\n" "$icon" "$t" "${NAME_OF[$t]:-?}" "$r"
done
echo "--------------------------------------------------------"
echo "  日志目录: $LOGDIR"
echo "  生产状态: kiro-mitm=$(sudo systemctl is-active kiro-mitm 2>/dev/null)  nginx=$(sudo systemctl is-active nginx 2>/dev/null)"
if [[ "$FAILED" == "0" ]]; then
  echo "  总判: ✅ 全绿"
  exit 0
else
  echo "  总判: ❌ 有层未通过(见上表 + 对应日志)"
  exit 1
fi
