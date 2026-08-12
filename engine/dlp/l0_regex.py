#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
"""L0 正则/词表(SPEC §5-L0)—— 亚毫秒,同步。

凭证类 → BLOCK;身份证/手机/邮箱 → REDACT。
白名单集中在此:官方示例 key、RFC2606 保留域名。
"""
from __future__ import annotations

import re

from .types import Hit, Layer, Verdict

# ---- 白名单(FP-05/FP-06)----
WHITELIST_TOKENS = {"AKIAIOSFODNN7EXAMPLE"}
# RFC2606 / RFC6761 保留域名后缀 —— 邮箱命中这些域一律 PASS
RESERVED_DOMAINS = ("example.com", "example.org", "example.net", "example.edu")
RESERVED_TLDS = (".example", ".test", ".invalid", ".localhost")

# ---- 模式 ----
_AWS_AK = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
_GCP_AK = re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")
# 40 字符 base64ish,需语境词
_AWS_SK_CTX = re.compile(
    r"(?:aws_secret_access_key|secret[_ ]?access[_ ]?key|aws.{0,12}secret)\W{0,4}"
    r"([A-Za-z0-9/+]{40})",
    re.IGNORECASE,
)
_CN_ID = re.compile(r"(?<!\d)\d{17}[\dxX](?!\d)")
_CN_PHONE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

# 手机需要的联系人语境(否则孤立数字串不判,防 L0-03 订单号误报)
_PHONE_CTX = re.compile(
    r"(电话|手机|联系|contact|phone|tel|mobile|联系人|call\b)", re.IGNORECASE
)
# 明确表明"这是流水号/订单号"的反语境 → 即便像手机也不当手机
_TRACKING_CTX = re.compile(
    r"(tracking|order|订单|流水|运单|快递|批次|serial|单号|no\.?|编号)", re.IGNORECASE
)

# "这是正则定义不是真值"(FP-10):字符类/量词特征
_REGEX_DEFN = re.compile(r"\[0-9A-Z[a-z]*\]\{\d+\}|\\d\{\d+\}|\[\\dA-Za-z")


def _cn_id_valid(s: str) -> bool:
    """GB11643 mod-11 校验位。"""
    if len(s) != 18:
        return False
    w = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    check = "10X98765432"
    try:
        total = sum(int(s[i]) * w[i] for i in range(17))
    except ValueError:
        return False
    return check[total % 11] == s[17].upper()


def is_reserved_email(addr: str) -> bool:
    """RFC2606/RFC6761 保留域名邮箱判定(FP-06)。

    公开 API:L0 与 L3(Presidio)**共用同一份**白名单,避免两处漂移。
    L3 上线后 Presidio 的 EmailRecognizer 会对 alice@example.com 报 EMAIL_ADDRESS,
    须用本函数在 L3 侧同样豁免,才能与 L0 一致地让保留域名邮箱 PASS(SPEC §5-L3)。
    """
    lower = addr.lower()
    dom = lower.split("@", 1)[1] if "@" in lower else lower
    if any(dom == d or dom.endswith("." + d) for d in RESERVED_DOMAINS):
        return True
    return any(dom.endswith(t) for t in RESERVED_TLDS)


def scan(text: str, source: str = "normalized") -> list[Hit]:
    hits: list[Hit] = []
    is_regex_defn = bool(_REGEX_DEFN.search(text))

    # AWS access key
    for m in _AWS_AK.finditer(text):
        tok = m.group(0)
        if tok in WHITELIST_TOKENS:
            continue  # 官方示例 key 单独出现 → 豁免(FP-05)
        if is_regex_defn:
            continue  # 模式定义文件里的 AKIA[0-9A-Z]{16} 不是真值(FP-10)
        hits.append(Hit(Layer.L0, "aws_access_key", "AWS_ACCESS_KEY",
                        m.span(), tok, Verdict.BLOCK, source=source))

    # AWS secret(需语境)
    for m in _AWS_SK_CTX.finditer(text):
        hits.append(Hit(Layer.L0, "aws_secret_key", "AWS_SECRET_KEY",
                        m.span(1), m.group(1), Verdict.BLOCK, source=source))

    # GCP api key
    for m in _GCP_AK.finditer(text):
        if is_regex_defn:
            continue
        hits.append(Hit(Layer.L0, "gcp_api_key", "GCP_API_KEY",
                        m.span(), m.group(0), Verdict.BLOCK, source=source))

    # 身份证(mod-11)
    has_id = False
    for m in _CN_ID.finditer(text):
        if _cn_id_valid(m.group(0)):
            has_id = True
            hits.append(Hit(Layer.L0, "cn_id_card", "CN_ID_CARD",
                            m.span(), m.group(0), Verdict.REDACT, source=source))

    # 手机:需联系人语境 或 与身份证同现;明确 tracking 语境则不判
    phone_ctx = bool(_PHONE_CTX.search(text)) or has_id
    tracking_ctx = bool(_TRACKING_CTX.search(text))
    for m in _CN_PHONE.finditer(text):
        if tracking_ctx and not phone_ctx:
            continue  # 订单/流水号语境下的 1xx 串不当手机(L0-03)
        if not phone_ctx:
            continue  # 无联系人语境的孤立号 → 不判(防 FP)
        hits.append(Hit(Layer.L0, "cn_phone", "CN_PHONE",
                        m.span(), m.group(0), Verdict.REDACT, source=source))

    # 邮箱:保留域名白名单 → PASS
    for m in _EMAIL.finditer(text):
        if is_reserved_email(m.group(0)):
            continue  # 断言字面量/示例域(FP-06)
        hits.append(Hit(Layer.L0, "email", "EMAIL",
                        m.span(), m.group(0), Verdict.REDACT, source=source))

    return hits
