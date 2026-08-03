"""L1 签名(SPEC §5-L1)—— ~10ms,同步。

detect-secrets/gitleaks 风格的前缀+结构签名。
关键区分:PEM 私钥 BLOCK vs 证书 PASS(FP-11);jwt.io demo PASS(FP-12);
占位符/lockfile 豁免。
"""
from __future__ import annotations

import re

from .types import Hit, Layer, Verdict

# PEM:按头精确区分私钥 vs 证书
_PEM_PRIVATE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----"
)
_PEM_CERT = re.compile(r"-----BEGIN CERTIFICATE-----")

_STRIPE_LIVE = re.compile(r"\bsk_live_[0-9a-zA-Z]{16,}\b")
_STRIPE_TEST = re.compile(r"\bsk_test_[0-9a-zA-Z]{16,}\b")
_GITHUB_PAT = re.compile(r"\bghp_[0-9A-Za-z]{36}\b")
_GITHUB_OTHER = re.compile(r"\b(gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b")
_OPENAI = re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b")
_SLACK = re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{6,}\.eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\b")

# 占位符白名单(L1-06 .env.example)
_PLACEHOLDER = re.compile(
    r"(CHANGE_?ME|YOUR[_\-].*[_\-]?HERE|<[^>]+>|xxx+|\.\.\.|placeholder|例如|示例|REPLACE)",
    re.IGNORECASE,
)
# jwt.io 公开 demo 的固定 payload(John Doe / sub 1234567890) → PASS(FP-12)
_JWT_DEMO_MARKERS = ("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9l",)


def _is_placeholder(window: str) -> bool:
    return bool(_PLACEHOLDER.search(window))


def scan(text: str, source: str = "normalized") -> list[Hit]:
    hits: list[Hit] = []

    if _PEM_PRIVATE.search(text):
        m = _PEM_PRIVATE.search(text)
        hits.append(Hit(Layer.L1, "pem_private_key", "PRIVATE_KEY",
                        m.span(), m.group(0), Verdict.BLOCK, source=source))
    # 证书:按 PEM 头精确区分 → PASS,不产 hit(FP-11)

    def _emit(rx, rule, entity, action=Verdict.BLOCK):
        for m in rx.finditer(text):
            tok = m.group(0)
            # 占位符窗口豁免
            lo = max(0, m.start() - 24)
            if _is_placeholder(text[lo:m.end() + 8]):
                continue
            hits.append(Hit(Layer.L1, rule, entity, m.span(), tok, action, source=source))

    _emit(_STRIPE_LIVE, "stripe_live", "STRIPE_KEY")
    _emit(_STRIPE_TEST, "stripe_test", "STRIPE_KEY")   # 测试密钥仍属密钥 → BLOCK(可在 fixture 里区分)
    _emit(_GITHUB_PAT, "github_pat", "GITHUB_PAT")
    _emit(_GITHUB_OTHER, "github_token", "GITHUB_PAT")
    _emit(_SLACK, "slack_token", "SLACK_TOKEN")

    # OpenAI:排除误伤 stripe sk_ 前缀
    for m in _OPENAI.finditer(text):
        tok = m.group(0)
        if tok.startswith("sk_live_") or tok.startswith("sk_test_"):
            continue
        lo = max(0, m.start() - 24)
        if _is_placeholder(text[lo:m.end() + 8]):
            continue
        hits.append(Hit(Layer.L1, "openai_key", "OPENAI_KEY",
                        m.span(), tok, Verdict.BLOCK, source=source))

    # JWT:公开 demo 白名单
    for m in _JWT.finditer(text):
        tok = m.group(0)
        if any(mk in tok for mk in _JWT_DEMO_MARKERS):
            continue  # jwt.io John Doe demo(FP-12)
        hits.append(Hit(Layer.L1, "jwt", "JWT", m.span(), tok, Verdict.BLOCK, source=source))

    return hits
