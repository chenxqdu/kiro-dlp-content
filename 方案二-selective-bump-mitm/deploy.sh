#!/usr/bin/env bash
#############################################
# Kiro DLP 验证节点 部署（选择性 bump / mitmproxy）
#
# 与生产 SNI 透传节点（deploy/）同构，但额外：
#   - nginx stream map 对 MITM_BUMP_DOMAIN 特判 → 转发到本机 mitmproxy(127.0.0.1:MITM_PORT)
#     其余 SNI 域名照旧 L4 透传（$ssl_preread_server_name:443）。
#   - user-data 在 EC2 上：装 mitmproxy(≥v11) + 现场生成企业 CA(root+中间, Name Constraints)
#     + 落地 kiro_addon.py + 启动硬化过的 mitmdump systemd 服务。
#   - 私钥全程只在 EC2 本机 /etc/mitm/certs 生成，永不外传、不进 git。
#
# ⚠️ 独立 state 文件（本目录 .deploy-state.env），与生产节点零耦合。
#
# 依赖：aws cli v2、jq、base64、openssl（本地）
# 用法：编辑 config.env 后执行  ./deploy.sh
#############################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.env"

STATE_FILE="${SCRIPT_DIR}/.deploy-state.env"
: > "${STATE_FILE}"   # 清空，记录本次创建的资源，供 cleanup.sh 使用

# ---------- 日志辅助 ----------
c_green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
c_yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }
c_red()    { printf '\033[0;31m%s\033[0m\n' "$*" >&2; }
log()  { c_green  "==> $*"; }
warn() { c_yellow "[!] $*"; }
die()  { c_red    "[x] $*"; exit 1; }

save_state() { echo "$1=\"$2\"" >> "${STATE_FILE}"; }

AWSCLI=(aws --region "${AWS_REGION}" --output json)

# ---------- 前置检查 ----------
command -v aws    >/dev/null || die "未找到 aws cli，请先安装 AWS CLI v2"
command -v jq     >/dev/null || die "未找到 jq，请先安装 jq"
command -v base64 >/dev/null || die "未找到 base64"
"${AWSCLI[@]}" sts get-caller-identity >/dev/null 2>&1 \
  || die "AWS 凭证无效或未配置，请先 aws configure / 设置环境变量"

# MITM 相关本地文件必须存在（将随 user-data 落地到 EC2）
GEN_CA_FILE="${SCRIPT_DIR}/gen-ca.sh"
ADDON_FILE="${SCRIPT_DIR}/kiro_addon.py"
[[ -f "${GEN_CA_FILE}" ]] || die "缺少 ${GEN_CA_FILE}"
[[ -f "${ADDON_FILE}"  ]] || die "缺少 ${ADDON_FILE}"

# 若启用 bump，校验 MITM_BUMP_DOMAIN 必须是 SNI_DOMAINS 中的一员
if [[ -n "${MITM_BUMP_DOMAIN}" ]]; then
  _hit="false"
  for d in "${SNI_DOMAINS[@]}"; do [[ "${d}" == "${MITM_BUMP_DOMAIN}" ]] && _hit="true"; done
  [[ "${_hit}" == "true" ]] || die "MITM_BUMP_DOMAIN=${MITM_BUMP_DOMAIN} 不在 SNI_DOMAINS 白名单中"
  log "选择性 bump 目标: ${MITM_BUMP_DOMAIN} -> 127.0.0.1:${MITM_PORT}（其余域名 L4 透传）"
else
  warn "MITM_BUMP_DOMAIN 为空 —— 退化为全透传模式（等价生产节点，不启用 mitmproxy）"
fi

ACCOUNT_ID="$("${AWSCLI[@]}" sts get-caller-identity --query Account --output text)"
log "AWS 账号: ${ACCOUNT_ID}  Region: ${AWS_REGION}  项目: ${PROJECT_NAME}"

TAG_SPEC_BASE="Key=Project,Value=${PROJECT_NAME}"

#############################################
# 1. 网络：复用或新建 VPC / 子网
#############################################
CREATED_NETWORK="false"
if [[ -n "${EXISTING_VPC_ID}" && -n "${EXISTING_SUBNET_ID}" ]]; then
  log "复用已有网络 VPC=${EXISTING_VPC_ID} Subnet=${EXISTING_SUBNET_ID}"
  VPC_ID="${EXISTING_VPC_ID}"
  SUBNET_ID="${EXISTING_SUBNET_ID}"
  SUBNET_VPC="$("${AWSCLI[@]}" ec2 describe-subnets --subnet-ids "${SUBNET_ID}" \
      --query 'Subnets[0].VpcId' --output text 2>/dev/null || echo "NONE")"
  [[ "${SUBNET_VPC}" == "${VPC_ID}" ]] \
    || die "子网 ${SUBNET_ID} 不属于 VPC ${VPC_ID}（实际: ${SUBNET_VPC}）"
elif [[ -z "${EXISTING_VPC_ID}" && -z "${EXISTING_SUBNET_ID}" ]]; then
  CREATED_NETWORK="true"
  log "新建 VPC (${NEW_VPC_CIDR}) / 子网 (${NEW_SUBNET_CIDR})"

  VPC_ID="$("${AWSCLI[@]}" ec2 create-vpc --cidr-block "${NEW_VPC_CIDR}" \
      --tag-specifications "ResourceType=vpc,Tags=[{${TAG_SPEC_BASE}},{Key=Name,Value=${PROJECT_NAME}-vpc}]" \
      --query 'Vpc.VpcId' --output text)"
  save_state VPC_ID "${VPC_ID}"
  "${AWSCLI[@]}" ec2 modify-vpc-attribute --vpc-id "${VPC_ID}" --enable-dns-support '{"Value":true}'
  "${AWSCLI[@]}" ec2 modify-vpc-attribute --vpc-id "${VPC_ID}" --enable-dns-hostnames '{"Value":true}'
  "${AWSCLI[@]}" ec2 wait vpc-available --vpc-ids "${VPC_ID}"
  log "VPC 创建完成: ${VPC_ID}"

  if [[ -z "${NEW_SUBNET_AZ}" ]]; then
    NEW_SUBNET_AZ="$("${AWSCLI[@]}" ec2 describe-availability-zones \
        --query 'AvailabilityZones[0].ZoneName' --output text)"
  fi
  SUBNET_ID="$("${AWSCLI[@]}" ec2 create-subnet --vpc-id "${VPC_ID}" \
      --cidr-block "${NEW_SUBNET_CIDR}" --availability-zone "${NEW_SUBNET_AZ}" \
      --tag-specifications "ResourceType=subnet,Tags=[{${TAG_SPEC_BASE}},{Key=Name,Value=${PROJECT_NAME}-subnet}]" \
      --query 'Subnet.SubnetId' --output text)"
  save_state SUBNET_ID "${SUBNET_ID}"
  "${AWSCLI[@]}" ec2 modify-subnet-attribute --subnet-id "${SUBNET_ID}" --map-public-ip-on-launch
  log "子网创建完成: ${SUBNET_ID} (${NEW_SUBNET_AZ})"

  IGW_ID="$("${AWSCLI[@]}" ec2 create-internet-gateway \
      --tag-specifications "ResourceType=internet-gateway,Tags=[{${TAG_SPEC_BASE}},{Key=Name,Value=${PROJECT_NAME}-igw}]" \
      --query 'InternetGateway.InternetGatewayId' --output text)"
  save_state IGW_ID "${IGW_ID}"
  "${AWSCLI[@]}" ec2 attach-internet-gateway --internet-gateway-id "${IGW_ID}" --vpc-id "${VPC_ID}"

  RT_ID="$("${AWSCLI[@]}" ec2 create-route-table --vpc-id "${VPC_ID}" \
      --tag-specifications "ResourceType=route-table,Tags=[{${TAG_SPEC_BASE}},{Key=Name,Value=${PROJECT_NAME}-rt}]" \
      --query 'RouteTable.RouteTableId' --output text)"
  save_state RT_ID "${RT_ID}"
  "${AWSCLI[@]}" ec2 create-route --route-table-id "${RT_ID}" \
      --destination-cidr-block "0.0.0.0/0" --gateway-id "${IGW_ID}" >/dev/null
  ASSOC_ID="$("${AWSCLI[@]}" ec2 associate-route-table --route-table-id "${RT_ID}" \
      --subnet-id "${SUBNET_ID}" --query 'AssociationId' --output text)"
  save_state RT_ASSOC_ID "${ASSOC_ID}"
  log "IGW/路由表创建完成: ${IGW_ID} / ${RT_ID}"
else
  die "config.env 网络配置错误：EXISTING_VPC_ID 与 EXISTING_SUBNET_ID 必须【同时填写】或【同时留空】"
fi
save_state CREATED_NETWORK "${CREATED_NETWORK}"
save_state VPC_ID "${VPC_ID}"
save_state SUBNET_ID "${SUBNET_ID}"

VPC_CIDR="$("${AWSCLI[@]}" ec2 describe-vpcs --vpc-ids "${VPC_ID}" \
    --query 'Vpcs[0].CidrBlock' --output text)"
log "VPC CIDR: ${VPC_CIDR}"

#############################################
# 2. 安全组：代理 EC2
#############################################
log "创建代理 EC2 安全组"
PROXY_SG_ID="$("${AWSCLI[@]}" ec2 create-security-group \
    --group-name "${PROJECT_NAME}-proxy-sg" \
    --description "Kiro DLP verify proxy EC2 SG" --vpc-id "${VPC_ID}" \
    --tag-specifications "ResourceType=security-group,Tags=[{${TAG_SPEC_BASE}},{Key=Name,Value=${PROJECT_NAME}-proxy-sg}]" \
    --query 'GroupId' --output text)"
save_state PROXY_SG_ID "${PROXY_SG_ID}"

# 443 入站仅当 INGRESS_443_CIDR 非空才开（用户已定：仅 SSM 本机自测，默认不开公网）。
# 默认 0 条 ingress —— SSM 走出站发起、本机 curl 走 loopback，均不需要 SG 入站。
# egress 保持 SG 默认全放行（覆盖 443→kiro 上游 + 9000→DLP + DNS）。
if [[ -n "${INGRESS_443_CIDR}" ]]; then
  "${AWSCLI[@]}" ec2 authorize-security-group-ingress --group-id "${PROXY_SG_ID}" \
      --protocol tcp --port 443 --cidr "${INGRESS_443_CIDR}" >/dev/null
  warn "已放行 443 入站来源 ${INGRESS_443_CIDR}"
else
  log "未开放 443 公网入站（仅 SSM + 本机 loopback 自测）"
fi
if [[ -n "${ADMIN_SSH_CIDR}" ]]; then
  "${AWSCLI[@]}" ec2 authorize-security-group-ingress --group-id "${PROXY_SG_ID}" \
      --protocol tcp --port 22 --cidr "${ADMIN_SSH_CIDR}" >/dev/null
  warn "已放行 22 端口来源 ${ADMIN_SSH_CIDR}"
else
  log "未开放 22 端口（使用 SSM Session Manager 登录）"
fi
log "代理安全组: ${PROXY_SG_ID}"

#############################################
# 2.5 SG-to-SG 联动：给 DLP 主机 SG 加 tcp/9000 from PROXY_SG（规格 D12）
#     - SG-to-SG 引用（非 CIDR），仅本 proxy SG 可达判定服务，同 VPC 生效。
#     - 幂等：先查是否已存在该规则；他人预置则不加、不回滚（DLP_SG_RULE_ADDED=false）。
#     - 本次新加的规则捕获 SecurityGroupRuleId 存入 state，供 cleanup 精确按 id 回滚。
#     顺序铁律：cleanup 必须【先 revoke 这条、再 delete PROXY_SG】，否则 DependencyViolation。
#############################################
DLP_SG_RULE_ADDED="false"
DLP_SG_RULE_ID=""
if [[ -n "${DLP_HOST_SG_ID:-}" && -n "${DLP_INSPECT_PORT:-}" ]]; then
  log "联动：检查 DLP 主机 SG ${DLP_HOST_SG_ID} 是否已放行 ${DLP_INSPECT_PORT} from ${PROXY_SG_ID}"
  # 幂等检查：是否已有 一条 引用 PROXY_SG 的 tcp/9000 ingress 规则
  EXIST_RULE="$("${AWSCLI[@]}" ec2 describe-security-group-rules \
      --filters "Name=group-id,Values=${DLP_HOST_SG_ID}" \
      --query "SecurityGroupRules[?!IsEgress && IpProtocol=='tcp' && FromPort==\`${DLP_INSPECT_PORT}\` && ToPort==\`${DLP_INSPECT_PORT}\` && ReferencedGroupInfo.GroupId=='${PROXY_SG_ID}'].SecurityGroupRuleId | [0]" \
      --output text 2>/dev/null || echo "None")"
  if [[ -n "${EXIST_RULE}" && "${EXIST_RULE}" != "None" ]]; then
    warn "  已存在放行规则 ${EXIST_RULE}（可能他人预置）—— 不重复添加、不纳入回滚"
    DLP_SG_RULE_ADDED="false"
  else
    log "  添加 ingress: tcp/${DLP_INSPECT_PORT} source=${PROXY_SG_ID} 到 ${DLP_HOST_SG_ID}"
    DLP_SG_RULE_ID="$("${AWSCLI[@]}" ec2 authorize-security-group-ingress \
        --group-id "${DLP_HOST_SG_ID}" \
        --ip-permissions "IpProtocol=tcp,FromPort=${DLP_INSPECT_PORT},ToPort=${DLP_INSPECT_PORT},UserIdGroupPairs=[{GroupId=${PROXY_SG_ID},Description=kiro-dlp-mitm-v2 proxy to DLP inspect}]" \
        --query 'SecurityGroupRules[0].SecurityGroupRuleId' --output text 2>/dev/null || echo "")"
    if [[ -n "${DLP_SG_RULE_ID}" && "${DLP_SG_RULE_ID}" != "None" ]]; then
      DLP_SG_RULE_ADDED="true"
      log "  已添加规则 ${DLP_SG_RULE_ID}"
    else
      die "给 DLP 主机 SG 添加 9000 入站失败（检查凭证是否有权改 ${DLP_HOST_SG_ID}）"
    fi
  fi
  save_state DLP_HOST_SG_ID "${DLP_HOST_SG_ID}"
  save_state DLP_SG_RULE_ADDED "${DLP_SG_RULE_ADDED}"
  save_state DLP_SG_RULE_ID "${DLP_SG_RULE_ID}"
else
  warn "未配置 DLP_HOST_SG_ID/DLP_INSPECT_PORT，跳过 SG 联动（addon 将无法到达判定服务）"
fi

#############################################
# 3. PrivateLink VPCE（验证节点默认关闭）
#############################################
if [[ "${ENABLE_PRIVATELINK}" == "true" ]]; then
  log "创建 VPCE 专用安全组（放行 VPC 内 443）"
  VPCE_SG_ID="$("${AWSCLI[@]}" ec2 create-security-group \
      --group-name "${PROJECT_NAME}-vpce-sg" \
      --description "Kiro DLP verify VPCE SG" --vpc-id "${VPC_ID}" \
      --tag-specifications "ResourceType=security-group,Tags=[{${TAG_SPEC_BASE}},{Key=Name,Value=${PROJECT_NAME}-vpce-sg}]" \
      --query 'GroupId' --output text)"
  save_state VPCE_SG_ID "${VPCE_SG_ID}"
  "${AWSCLI[@]}" ec2 authorize-security-group-ingress --group-id "${VPCE_SG_ID}" \
      --protocol tcp --port 443 --cidr "${VPC_CIDR}" >/dev/null

  for svc in "q" "codewhisperer"; do
    SVC_NAME="com.amazonaws.${AWS_REGION}.${svc}"
    log "创建 VPCE: ${SVC_NAME}"
    VPCE_ID="$("${AWSCLI[@]}" ec2 create-vpc-endpoint \
        --vpc-id "${VPC_ID}" --vpc-endpoint-type Interface \
        --service-name "${SVC_NAME}" \
        --subnet-ids "${SUBNET_ID}" \
        --security-group-ids "${VPCE_SG_ID}" \
        --private-dns-enabled \
        --tag-specifications "ResourceType=vpc-endpoint,Tags=[{${TAG_SPEC_BASE}},{Key=Name,Value=${PROJECT_NAME}-vpce-${svc}}]" \
        --query 'VpcEndpoint.VpcEndpointId' --output text)"
    save_state "VPCE_${svc}_ID" "${VPCE_ID}"
    log "  -> ${VPCE_ID}"
  done
  warn "VPCE 需数分钟变为 available，EC2 启动期间会并行就绪"
else
  warn "ENABLE_PRIVATELINK=false，跳过 VPCE（DNS 走公网解析；mitmproxy 上游也走公网）"
fi

#############################################
# 4. SSM 角色（免密登录/运维）
#############################################
log "配置 IAM 角色（SSM）"
ROLE_NAME="${PROJECT_NAME}-ec2-role"
INSTANCE_PROFILE="${PROJECT_NAME}-ec2-profile"

if ! aws iam get-role --role-name "${ROLE_NAME}" >/dev/null 2>&1; then
  aws iam create-role --role-name "${ROLE_NAME}" \
    --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' >/dev/null
  save_state IAM_ROLE_CREATED "true"
  aws iam attach-role-policy --role-name "${ROLE_NAME}" \
    --policy-arn "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore" >/dev/null
  log "IAM 角色创建完成: ${ROLE_NAME}"
else
  warn "IAM 角色 ${ROLE_NAME} 已存在，复用"
fi
save_state IAM_ROLE_NAME "${ROLE_NAME}"

if ! aws iam get-instance-profile --instance-profile-name "${INSTANCE_PROFILE}" >/dev/null 2>&1; then
  aws iam create-instance-profile --instance-profile-name "${INSTANCE_PROFILE}" >/dev/null
  aws iam add-role-to-instance-profile --instance-profile-name "${INSTANCE_PROFILE}" \
    --role-name "${ROLE_NAME}" >/dev/null
  save_state IAM_PROFILE_CREATED "true"
  log "实例配置文件创建完成，等待 IAM 传播..."
  sleep 12
else
  warn "实例配置文件 ${INSTANCE_PROFILE} 已存在，复用"
fi
save_state IAM_PROFILE_NAME "${INSTANCE_PROFILE}"

#############################################
# 5. 生成 user-data
#############################################
log "生成 user-data（nginx 选择性 bump + mitmproxy + 企业 CA）"

# --- 组装 SNI map：bump 域名 → 本机 mitmproxy；其余 → L4 透传 ---
MAP_LINES=""
for d in "${SNI_DOMAINS[@]}"; do
  if [[ -n "${MITM_BUMP_DOMAIN}" && "${d}" == "${MITM_BUMP_DOMAIN}" ]]; then
    # bump：字面地址 127.0.0.1:PORT，不经 resolver
    MAP_LINES+="        ${d}  127.0.0.1:${MITM_PORT};"$'\n'
  else
    # 透传：$ssl_preread_server_name:443（单引号防止本地展开，落地后由 nginx 解析）
    MAP_LINES+="        ${d}"
    MAP_LINES+='  $ssl_preread_server_name:443;'$'\n'
  fi
done

# --- 把 CA 生成脚本 + addon 编码进 user-data（gzip+单行 base64）---
#     ★ 必须 gzip 压缩：EC2 user-data 上限 25600 编码字节；未压缩时 addon(20KB)+ca(6.5KB)
#       会撑爆。gzip -9 后二者合计约 11KB base64，总 user-data 稳稳在限内。落地端 base64 -d | gunzip。
CA_SCRIPT_B64="$(gzip -9 -c "${GEN_CA_FILE}" | base64 | tr -d '\n')"
ADDON_B64="$(gzip -9 -c "${ADDON_FILE}" | base64 | tr -d '\n')"

# 是否启用 mitmproxy（仅当 bump 域名非空）
ENABLE_MITM="false"
[[ -n "${MITM_BUMP_DOMAIN}" ]] && ENABLE_MITM="true"

USERDATA_FILE="$(mktemp)"
cat > "${USERDATA_FILE}" <<USERDATA
#!/bin/bash
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y nginx libnginx-mod-stream dnsutils openssl python3-venv python3-pip

#############################################
# nginx stream：选择性 bump + L4 透传
#############################################
cat > /etc/nginx/nginx.conf <<'NGINXCONF'
user www-data;
worker_processes auto;
worker_rlimit_nofile 65535;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 16384;
    multi_accept on;
    use epoll;
}

stream {
    map \$ssl_preread_server_name \$backend {
${MAP_LINES}        default                                "";
    }

    resolver 169.254.169.253 valid=30s ipv6=off;
    resolver_timeout 5s;

    log_format sni '\$remote_addr [\$time_local] sni="\$ssl_preread_server_name" '
                   'backend="\$backend" status=\$status sent=\$bytes_sent recv=\$bytes_received '
                   'duration=\$session_time';
    access_log /var/log/nginx/sni.log sni buffer=64k flush=5s;
    error_log  /var/log/nginx/sni_error.log warn;

    tcp_nodelay on;

    server {
        listen 443 reuseport;
        proxy_pass \$backend;
        ssl_preread on;
        proxy_connect_timeout 10s;
        proxy_timeout 600s;
        proxy_socket_keepalive on;
    }
}

http {
    server {
        listen 80 default_server;
        return 404;
    }
}
NGINXCONF

nginx -t
systemctl enable nginx
systemctl restart nginx
echo "nginx ready" > /var/log/kiro-mitm-bootstrap.log

#############################################
# mitmproxy 选择性 bump（仅 ENABLE_MITM=true 时）
#############################################
if [[ "${ENABLE_MITM}" == "true" ]]; then

  # --- 落地 CA 生成脚本 + DLP addon ---
  mkdir -p /opt/kiro-mitm "${MITM_CA_DIR}"
  echo '${CA_SCRIPT_B64}' | base64 -d | gunzip > /opt/kiro-mitm/gen-ca.sh
  echo '${ADDON_B64}'     | base64 -d | gunzip > /etc/mitm/kiro_addon.py
  chmod +x /opt/kiro-mitm/gen-ca.sh

  # --- 安装 mitmproxy（独立 venv）+ 主版本断言 ≥ ${MITM_MIN_MAJOR} ---
  python3 -m venv /opt/mitm-venv
  /opt/mitm-venv/bin/pip install --quiet --upgrade pip
  /opt/mitm-venv/bin/pip install --quiet 'mitmproxy>=${MITM_MIN_MAJOR}'
  # httpx 首选后端（连接池 + connect/read 分离超时）；装失败不致命，addon 自动回落
  # asyncio.to_thread + 标准库 urllib（功能等价，同样不阻塞事件循环）。
  /opt/mitm-venv/bin/pip install --quiet httpx || echo "httpx 安装失败，addon 走 urllib 回落" >> /var/log/kiro-mitm-bootstrap.log
  MITM_MAJOR=\$(/opt/mitm-venv/bin/mitmdump --version 2>/dev/null | grep -oiE 'mitmproxy[: ]+[0-9]+' | grep -oE '[0-9]+' | head -1)
  if [[ -z "\${MITM_MAJOR}" || "\${MITM_MAJOR}" -lt ${MITM_MIN_MAJOR} ]]; then
    echo "FATAL: mitmproxy major=\${MITM_MAJOR} < ${MITM_MIN_MAJOR}" | tee -a /var/log/kiro-mitm-bootstrap.err
    exit 1
  fi
  echo "mitmproxy major=\${MITM_MAJOR} OK" >> /var/log/kiro-mitm-bootstrap.log

  # --- 非 root 运行用户 ---
  id mitm >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin mitm

  # --- 现场生成企业 CA（root + 中间, Name Constraints=${MITM_CA_PERMITTED_DNS}）---
  export MITM_CA_DIR="${MITM_CA_DIR}"
  export MITM_CA_ROOT_CN="${MITM_CA_ROOT_CN}"
  export MITM_CA_INTER_CN="${MITM_CA_INTER_CN}"
  export MITM_CA_PERMITTED_DNS="${MITM_CA_PERMITTED_DNS}"
  export MITM_CA_ROOT_DAYS="${MITM_CA_ROOT_DAYS}"
  export MITM_CA_INTER_DAYS="${MITM_CA_INTER_DAYS}"
  bash /opt/kiro-mitm/gen-ca.sh

  # confdir 归 mitm 所有（mitmproxy 需读私钥、写派生证书）
  chown -R mitm:mitm /etc/mitm
  chmod 700 "${MITM_CA_DIR}"

  # --- 硬化的 systemd 服务 ---
  cat > /etc/systemd/system/kiro-mitm.service <<UNIT
[Unit]
Description=Kiro DLP mitmproxy (selective bump: ${MITM_BUMP_DOMAIN})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mitm
Group=mitm
Environment=HOME=/etc/mitm
# stdout 行缓冲下 systemd(非TTY)会吞掉 addon 日志 —— 关缓冲，确保自检/裁决日志进 journald。
Environment=PYTHONUNBUFFERED=1
# --- 联动 addon 配置注入（本地展开 config.env 的值）---
Environment=DLP_INSPECT_URL=${DLP_INSPECT_URL}
Environment=DLP_FAIL_MODE=${DLP_FAIL_MODE}
Environment=MITM_BUMP_DOMAIN=${MITM_BUMP_DOMAIN}
Environment=DLP_TIMEOUT=${DLP_TIMEOUT}
Environment=DLP_MAX_BODY_BYTES=${DLP_MAX_BODY_BYTES}
ExecStart=/opt/mitm-venv/bin/mitmdump \\
  --mode reverse:https://${MITM_BUMP_DOMAIN}@127.0.0.1:${MITM_PORT} \\
  --set keep_host_header=true \\
  --set upstream_cert=false \\
  --set connection_strategy=lazy \\
  --set confdir=${MITM_CA_DIR} \\
  -s /etc/mitm/kiro_addon.py
Restart=on-failure
RestartSec=3
# --- 硬化 ---
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
ReadWritePaths=/etc/mitm
AmbientCapabilities=
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
  systemctl enable kiro-mitm
  systemctl start kiro-mitm
  echo "kiro-mitm service started" >> /var/log/kiro-mitm-bootstrap.log

else
  echo "ENABLE_MITM=false, mitmproxy skipped (full passthrough)" >> /var/log/kiro-mitm-bootstrap.log
fi
USERDATA

#############################################
# 6. 查最新 Ubuntu 24.04 AMI + 启动 EC2
#############################################
log "查询 Ubuntu 24.04 (${INSTANCE_ARCH}) 最新 AMI"
AMI_ID="$("${AWSCLI[@]}" ssm get-parameter \
    --name "/aws/service/canonical/ubuntu/server/24.04/stable/current/${INSTANCE_ARCH}/hvm/ebs-gp3/ami-id" \
    --query 'Parameter.Value' --output text 2>/dev/null || echo "")"
if [[ -z "${AMI_ID}" || "${AMI_ID}" == "None" ]]; then
  AMI_ID="$("${AWSCLI[@]}" ec2 describe-images --owners 099720109477 \
      --filters "Name=name,Values=ubuntu/images/hvm-ssd*/ubuntu-noble-24.04-${INSTANCE_ARCH}-server-*" \
                "Name=state,Values=available" \
      --query 'reverse(sort_by(Images,&CreationDate))[0].ImageId' --output text)"
fi
[[ -n "${AMI_ID}" && "${AMI_ID}" != "None" ]] || die "未找到 Ubuntu 24.04 AMI"
log "AMI: ${AMI_ID}"

RUN_ARGS=(
  ec2 run-instances
  --image-id "${AMI_ID}"
  --instance-type "${INSTANCE_TYPE}"
  --subnet-id "${SUBNET_ID}"
  --security-group-ids "${PROXY_SG_ID}"
  --iam-instance-profile "Name=${INSTANCE_PROFILE}"
  --associate-public-ip-address
  --metadata-options "HttpTokens=required,HttpEndpoint=enabled"
  --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=${EBS_SIZE_GB},VolumeType=gp3,DeleteOnTermination=true}"
  --user-data "file://${USERDATA_FILE}"
  --tag-specifications "ResourceType=instance,Tags=[{${TAG_SPEC_BASE}},{Key=Name,Value=${PROJECT_NAME}-ec2}]"
)
[[ -n "${KEY_NAME}" ]] && RUN_ARGS+=(--key-name "${KEY_NAME}")

log "启动 EC2 实例..."
INSTANCE_ID="$("${AWSCLI[@]}" "${RUN_ARGS[@]}" --query 'Instances[0].InstanceId' --output text)"
save_state INSTANCE_ID "${INSTANCE_ID}"
rm -f "${USERDATA_FILE}"
log "实例已创建: ${INSTANCE_ID}，等待 running..."
"${AWSCLI[@]}" ec2 wait instance-running --instance-ids "${INSTANCE_ID}"

#############################################
# 7. 分配并绑定 EIP
#############################################
log "分配 EIP 并绑定"
EIP_ALLOC_ID="$("${AWSCLI[@]}" ec2 allocate-address --domain vpc \
    --tag-specifications "ResourceType=elastic-ip,Tags=[{${TAG_SPEC_BASE}},{Key=Name,Value=${PROJECT_NAME}-eip}]" \
    --query 'AllocationId' --output text)"
save_state EIP_ALLOC_ID "${EIP_ALLOC_ID}"
"${AWSCLI[@]}" ec2 associate-address --instance-id "${INSTANCE_ID}" \
    --allocation-id "${EIP_ALLOC_ID}" >/dev/null
EIP="$("${AWSCLI[@]}" ec2 describe-addresses --allocation-ids "${EIP_ALLOC_ID}" \
    --query 'Addresses[0].PublicIp' --output text)"
save_state EIP "${EIP}"

PRIVATE_IP="$("${AWSCLI[@]}" ec2 describe-instances --instance-ids "${INSTANCE_ID}" \
    --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text)"

#############################################
# 8. 输出结果 + 生成客户端 hosts 片段
#############################################
HOSTS_FILE="${SCRIPT_DIR}/client-hosts.txt"
{
  echo "# === Kiro DLP 验证节点 客户端 hosts（指向验证节点 EIP）==="
  echo "# 注意：这是【验证客户端】的 hosts。EC2 本机绝不改 hosts，"
  echo "#       否则 mitmproxy 上游会解析回自己形成环路。"
  for d in "${SNI_DOMAINS[@]}"; do
    printf '%-15s %s\n' "${EIP}" "${d}"
  done
} > "${HOSTS_FILE}"

echo
c_green "=================================================="
c_green "     Kiro DLP 验证节点 部署完成 ✅"
c_green "=================================================="
cat <<SUMMARY
  Region        : ${AWS_REGION}
  项目/前缀     : ${PROJECT_NAME}
  VPC           : ${VPC_ID} (${VPC_CIDR}) $( [[ ${CREATED_NETWORK} == true ]] && echo '[新建]' || echo '[复用]' )
  Subnet        : ${SUBNET_ID}
  实例 ID       : ${INSTANCE_ID} (${INSTANCE_TYPE}, ${INSTANCE_ARCH})
  公网 EIP      : ${EIP}
  私有 IP       : ${PRIVATE_IP}
  PrivateLink   : ${ENABLE_PRIVATELINK}
  选择性 bump   : ${MITM_BUMP_DOMAIN:-（无，全透传）} $( [[ ${ENABLE_MITM} == true ]] && echo "-> 127.0.0.1:${MITM_PORT}" )
  客户端 hosts  : ${HOSTS_FILE}

  链路：客户端 --443--> nginx(ssl_preread 读 SNI)
        ├─ SNI=${MITM_BUMP_DOMAIN:-<bump域名>} → 127.0.0.1:${MITM_PORT} → mitmproxy(解密/观测/重加密) → 真实上游
        └─ 其余白名单域名 → \$ssl_preread_server_name:443（L4 透传，从不解密）

  ⚠️ 验证前置门槛（必须在客户端信任我们的 root CA，否则 bump 域名握手失败）：
     1) 从 EC2 取根证书（无私钥、可公开）：
          aws ssm start-session --target ${INSTANCE_ID} --region ${AWS_REGION}
          sudo cat ${MITM_CA_DIR}/root-ca-for-clients.crt   # 复制到客户端
     2) 按 Kiro 各 TLS 栈分别信任（禁用 NODE_TLS_REJECT_UNAUTHORIZED=0）：
          系统/Chromium : 导入系统信任库
          Node/Electron : NODE_EXTRA_CA_CERTS=<root.crt>
          Rust CLI      : SSL_CERT_FILE / AWS_CA_BUNDLE=<root.crt>
          Bun TUI       : NODE_USE_SYSTEM_CA=1 + 系统库

  验证步骤（客户端）：
     - 追加 ${HOSTS_FILE} 到 hosts 并刷新 DNS：
          macOS : sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder
     - bump 域名（应能用我们 CA 完成握手，openssl 应显示颁发者=中间CA）：
          openssl s_client -connect ${MITM_BUMP_DOMAIN}:443 -servername ${MITM_BUMP_DOMAIN} </dev/null 2>/dev/null | openssl x509 -noout -issuer -subject
     - 透传域名（应显示 AWS 真实证书，颁发者=Amazon）：
          openssl s_client -connect q.${AWS_REGION}.amazonaws.com:443 -servername q.${AWS_REGION}.amazonaws.com </dev/null 2>/dev/null | openssl x509 -noout -issuer

  看日志（EC2，无需 22）：
     aws ssm start-session --target ${INSTANCE_ID} --region ${AWS_REGION}
     sudo tail -f /var/log/nginx/sni.log              # L4 层：SNI/backend/流量
     sudo journalctl -u kiro-mitm -f                  # mitmproxy：KIRO-INFER/KIRO-OTHER 观测日志
     sudo tail -n 50 /var/log/kiro-mitm-bootstrap.log # 引导过程

  资源清理： ./cleanup.sh
SUMMARY
