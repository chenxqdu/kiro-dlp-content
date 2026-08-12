#!/usr/bin/env bash
#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
#############################################
# 企业 CA 生成（在验证节点 EC2 上现场执行）
#
# 产出三级信任结构：
#   Root CA（自签，信任锚，无 Name Constraints）
#     └─ Issuing/Intermediate CA（Name Constraints: 只允许签 kiro.dev；CA:TRUE pathlen:0）
#          └─ mitmproxy 用它现场签发叶子证书
#
# mitmproxy-ca.pem = 中间CA私钥 + 中间CA证书 + 根证书（key-first）。
# ★ 必须把 root.crt 也拼进来：mitmproxy 发链时会把本文件里【签发证书之后】的所有证书
#   附到叶子后一起下发。只放 inter 时，客户端仅收到 [叶子]，手上无中间CA → 无法建链到 root
#   （openssl Verify code 21）。放 inter+root 后下发 [叶子, inter, root]，客户端信任 root 即建链成功。
# Name Constraints 挂在【中间 CA】而非 root —— 所有 TLS 栈都会强制校验中间 CA 的
# NC（RFC 5280 §4.2.1.10），从而物理上限制这套 CA 只能伪造 kiro.dev 证书，
# 绝不可能伪造 codewhisperer/q 等 SigV4 域名（那些流量我们从不解密）。
#
# ⚠️ 所有私钥仅存在于本机 ${MITM_CA_DIR}，权限 600，永不外传、不进 git。
# 客户端只需分发 root.crt（公开证书，无私钥）。
#
# 幂等：CA 已存在则跳过（不覆盖，避免换 CA 导致已分发信任失效）。
#############################################
set -euo pipefail

CA_DIR="${MITM_CA_DIR:-/etc/mitm/certs}"
ROOT_CN="${MITM_CA_ROOT_CN:-Kiro-DLP-Verify Root CA}"
INTER_CN="${MITM_CA_INTER_CN:-Kiro-DLP-Verify Issuing CA}"
PERMITTED_DNS="${MITM_CA_PERMITTED_DNS:-kiro.dev}"
ROOT_DAYS="${MITM_CA_ROOT_DAYS:-3650}"
INTER_DAYS="${MITM_CA_INTER_DAYS:-1825}"
KEY_BITS="4096"

MITM_PEM="${CA_DIR}/mitmproxy-ca.pem"

if [[ -f "${MITM_PEM}" ]]; then
  echo "[gen-ca] ${MITM_PEM} 已存在，跳过生成（如需重建请先手工删除 ${CA_DIR}）"
  exit 0
fi

echo "[gen-ca] 生成 CA 到 ${CA_DIR}"
mkdir -p "${CA_DIR}"
chmod 700 "${CA_DIR}"
umask 077   # 之后所有生成物默认 600

# ---------- 1. Root CA（信任锚，自签）----------
openssl genrsa -out "${CA_DIR}/root.key" "${KEY_BITS}"
openssl req -x509 -new -nodes -key "${CA_DIR}/root.key" -sha256 \
  -days "${ROOT_DAYS}" -out "${CA_DIR}/root.crt" \
  -subj "/CN=${ROOT_CN}" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"

# ---------- 2. Intermediate/Issuing CA（挂 Name Constraints）----------
openssl genrsa -out "${CA_DIR}/inter.key" "${KEY_BITS}"
openssl req -new -key "${CA_DIR}/inter.key" \
  -out "${CA_DIR}/inter.csr" -subj "/CN=${INTER_CN}"

# 中间 CA 扩展：CA:TRUE pathlen:0 + keyCertSign + 关键 Name Constraints。
# permitted;DNS 不带前导点 → 匹配该域及其全部子域（runtime.us-east-1.kiro.dev ⊂ kiro.dev）。
#
# ★ 只约束 DNS，【绝不】加 excluded IP —— 这是踩过的坑（RFC 5280 §4.2.1.10 + 实测 code 48）：
#   mitmproxy 现场签发叶子时会把【连接目标 IP】自动写进 SAN
#   （实测：SAN = DNS:runtime.us-east-1.kiro.dev, IP Address:<后端IP>）。
#   若中间 CA 排除全部 IP 子树（0.0.0.0/0 + ::/0），叶子的 IP-SAN 就落入 excluded 子树，
#   TLSv1.3 严格校验（curl / 真实 Kiro 客户端）直接判 "excluded subtree violation (code 48)"，
#   握手被拒 —— 所有 bump 叶子全废。
#   RFC 5280 语义：permitted 只约束【出现过的名称类型】。只写 permitted DNS 时，IP 类型
#   既不 permitted 也不 excluded → 默认允许。于是 DNS 被牢牢收紧到 kiro.dev（物理上无法
#   伪造 codewhisperer/q 等 SigV4 域），而 mitmproxy 必需的 IP-SAN 得以放行。攻击面收紧目标
#   （只能签 kiro.dev 子域）已由 permitted DNS 单独达成，excluded IP 画蛇添足且自伤。
cat > "${CA_DIR}/inter.ext" <<EOF
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
nameConstraints=critical,@nc

[nc]
permitted;DNS.0=${PERMITTED_DNS}
EOF

openssl x509 -req -in "${CA_DIR}/inter.csr" \
  -CA "${CA_DIR}/root.crt" -CAkey "${CA_DIR}/root.key" -CAcreateserial \
  -sha256 -days "${INTER_DAYS}" \
  -extfile "${CA_DIR}/inter.ext" \
  -out "${CA_DIR}/inter.crt"

# ---------- 3. 组装 mitmproxy-ca.pem（key-first：中间CA私钥 + 中间CA证书 + 根证书）----------
# root.crt 附在末尾 → mitmproxy 下发链含 [叶子, inter, root]，客户端仅信任 root 即可完整建链。
cat "${CA_DIR}/inter.key" "${CA_DIR}/inter.crt" "${CA_DIR}/root.crt" > "${MITM_PEM}"
chmod 600 "${MITM_PEM}"

# 便于分发的纯证书拷贝（无私钥）
cp "${CA_DIR}/root.crt"  "${CA_DIR}/root-ca-for-clients.crt"
cp "${CA_DIR}/inter.crt" "${CA_DIR}/inter-ca.crt"
chmod 644 "${CA_DIR}/root-ca-for-clients.crt" "${CA_DIR}/inter-ca.crt"

# 清理中间产物（私钥保留在机内，仅删无用文件）
rm -f "${CA_DIR}/inter.csr" "${CA_DIR}/inter.ext"

echo "[gen-ca] 完成。校验中间 CA 的 Name Constraints："
openssl x509 -noout -text -in "${CA_DIR}/inter.crt" \
  | grep -A4 -E 'X509v3 (Name Constraints|Basic Constraints|Key Usage)' || true

echo "[gen-ca] 校验链：root -> inter"
openssl verify -CAfile "${CA_DIR}/root.crt" "${CA_DIR}/inter.crt" || \
  echo "[gen-ca][warn] 链校验未通过，请检查"

cat <<NOTE

[gen-ca] 客户端分发说明：
  只需把  ${CA_DIR}/root-ca-for-clients.crt  安装进【验证客户端】的信任库。
  Kiro 有多套 TLS 栈，分别信任方式：
    - 系统/Chromium : 导入系统钥匙串（macOS）或 update-ca-certificates（Linux）
    - Node/Electron : 设 NODE_EXTRA_CA_CERTS=<root.crt 路径>（禁用 NODE_TLS_REJECT_UNAUTHORIZED=0！）
    - Rust CLI      : 设 SSL_CERT_FILE / AWS_CA_BUNDLE=<root.crt 路径>
    - Bun TUI       : 设 NODE_USE_SYSTEM_CA=1 并将 root 装入系统库
  私钥 (root.key / inter.key / mitmproxy-ca.pem) 永不离开本机。
NOTE
