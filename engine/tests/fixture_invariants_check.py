"""独立不变量交叉校验器(SPEC §7 line 268:"对抗审计据此校验 fixture 正确性")。

**为什么存在 / 它解决什么问题**
harness(run_offline.py)拿 fixture 喂引擎、比对 verdict。但如果 fixture *本身*
造错了——比如声明 `must_hit CN_ID_CARD` 却在 content 里写了个 mod-11 校验位错误的
假身份证——引擎会**正确地不命中**,harness 报 miss。此时"错"在 fixture,不在引擎;
没有本校验器我会误判成"引擎漏拦"去改引擎,越改越坏。

本校验器**在跑矩阵之前**先把 fixture 自身的内部一致性钉死:纯从 `content` 字面量
**从头独立重算**每条结构性不变量(GB11643 mod-11、Luhn、base64/hex 往返、rot13、
Shannon 熵、PEM 头、RFC2606 保留域名成员判定),再与 fixture 声明的 `invariants[]`
和 `expected{}` **三方对账**,只在出现**数学确定的矛盾**时报 FLAG。

**独立性铁律**:绝不 import 引擎的 `_cn_id_valid`/`_luhn`/`is_reserved_email`——
本文件重新实现同一套算法。两套独立实现对同一 content 判定若不一致,本身即抓 bug 的机制。
(注:mod-11/Luhn 各只有一种正确算法,正确 ID 上两者按构造一致;价值在于抓 fixture
作者手滑写错校验位——即声明"过 mod-11"实则不过——这正是首要威胁。)

**保守性铁律**:每条 HARD flag 必须是"content 结构上不可能产生 expected 声明"的铁证,
不报启发式猜测——一个乱报的校验器会自毁信任(正是历史上被证伪的 OVERSTATED 失败模式)。
拿不准的一律降级为 NOTE(不影响退出码)。

用法:
    python3 -m tests.fixture_invariants_check          # 校验全部 suite
    python3 tests/fixture_invariants_check.py --suite 2
fixtures 未落地时安全:打印"待生成"并 exit 0。发现矛盾 exit 1。
"""
from __future__ import annotations

import base64
import binascii
import codecs
import json
import math
import re
import sys
import unicodedata
from pathlib import Path

_ENGINE_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = _ENGINE_ROOT / "tests" / "fixtures"

# ── 独立常量(本校验器自持,不从引擎导入)────────────────────────────────
# RFC2606 / RFC6761 保留域名(FP-06):与引擎独立的一份;RFC 固定,不会漂。
RESERVED_DOMAINS = ("example.com", "example.org", "example.net", "example.edu")
RESERVED_TLDS = (".example", ".test", ".invalid", ".localhost")
# AWS 官方示例 key(FP-05):文档公开值,单独出现应被豁免。
OFFICIAL_EXAMPLE_AWS_KEYS = {"AKIAIOSFODNN7EXAMPLE"}
# Presidio 官方测试卡号(FP-08):Luhn 通过但非真卡,不应命中。
TEST_CARDS = {"4111111111111111", "5555555555554444", "378282246310005",
              "4242424242424242", "5105105105105100"}

_CN_DIGITS = str.maketrans("零一二三四五六七八九〇", "01234567890")
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍﻿⁠᠎"), None)

_RE_CN_ID = re.compile(r"(?<!\d)\d{17}[\dxX](?!\d)")
_RE_AWS_AK = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_RE_GCP_AK = re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")
_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_RE_DIGIT_RUN = re.compile(r"\d[\d ._-]{11,21}\d")   # 13–19 位卡号(含分隔符)
_RE_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_RE_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
_RE_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{16,}")
# "这是正则定义不是真值"(FP-10),与引擎独立的一份判据
_RE_REGEX_DEFN = re.compile(r"\[0-9A-Z[a-z]*\]\{\d+\}|\\d\{\d+\}|\[\\dA-Za-z")
_PRINTABLE = re.compile(rb"^[\x09\x0a\x0d\x20-\x7e]+$")


# ── 独立重实现的判定原语 ──────────────────────────────────────────────
def cn_id_mod11(s: str) -> bool:
    """GB11643-1999 mod-11 校验位。独立实现,不 import 引擎。"""
    if len(s) != 18:
        return False
    w = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    check = "10X98765432"
    try:
        total = sum(int(s[i]) * w[i] for i in range(17))
    except ValueError:
        return False
    return check[total % 11] == s[17].upper()


def cn_id_expected_check(s: str) -> str:
    """返回该 17 位前缀**应有**的校验位(用于报告手滑写错的正确值)。"""
    if len(s) < 17:
        return "?"
    w = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    check = "10X98765432"
    try:
        total = sum(int(s[i]) * w[i] for i in range(17))
    except ValueError:
        return "?"
    return check[total % 11]


def luhn(num: str) -> bool:
    """Luhn 校验。独立实现。"""
    digits = [int(d) for d in num if d.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def is_reserved_domain_email(addr: str) -> bool:
    """RFC2606 保留域名邮箱判定。独立实现,不 import 引擎。"""
    lower = addr.lower()
    dom = lower.split("@", 1)[1] if "@" in lower else lower
    if any(dom == d or dom.endswith("." + d) for d in RESERVED_DOMAINS):
        return True
    return any(dom.endswith(t) for t in RESERVED_TLDS)


def try_b64(s: str) -> str | None:
    pad = (-len(s)) % 4
    try:
        raw = base64.b64decode(s + "=" * pad, validate=True)
    except (binascii.Error, ValueError):
        return None
    if raw and _PRINTABLE.match(raw):
        try:
            return raw.decode("ascii")
        except UnicodeDecodeError:
            return None
    return None


def try_hex(s: str) -> str | None:
    if len(s) % 2:
        return None
    try:
        raw = bytes.fromhex(s)
    except ValueError:
        return None
    if raw and _PRINTABLE.match(raw):
        try:
            return raw.decode("ascii")
        except UnicodeDecodeError:
            return None
    return None


def rot13(s: str) -> str:
    return codecs.encode(s, "rot13")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def normalize_cn(text: str) -> str:
    """NFKC + 去零宽 + 中文数字→阿拉伯(独立,用于抓 EVA-11 中文数字身份证)。"""
    t = unicodedata.normalize("NFKC", text)
    t = t.translate(_ZERO_WIDTH)
    return t.translate(_CN_DIGITS)


# ── content 展开:收集全部字符串叶子 + 解码/归一化派生形 ─────────────────
def string_leaves(content) -> list[str]:
    """content 为 str → [content];为 dict/list(mcp_call)→ 递归全部字符串叶子。"""
    out: list[str] = []

    def rec(o):
        if isinstance(o, str):
            out.append(o)
        elif isinstance(o, dict):
            for v in o.values():
                rec(v)
        elif isinstance(o, list):
            for v in o:
                rec(v)
    rec(content)
    return out


def derived_texts(leaves: list[str]) -> tuple[list[str], set[str]]:
    """原文叶子 + 归一化(中文数字) + base64/hex/rot13 解码派生,全部并入待判池。

    这样 base64 藏的 AKIA、中文数字写的身份证、rot13 藏的 secret 都能被独立重算看到。

    返回 (pool, rot13_forms):rot13_forms 单列出来,因为引擎(engine.py §4 收尾,
    第 156-160 行)对 `decoded:rot13` 变体**只保 BLOCK 级命中,REDACT 级一律丢弃**——
    rot13 是对合变换,对良性明文整体 rot13 会"变造"出看似真值的伪 PII
    (如 rot13("support@example.com")=fhccbeg@rknzcyr.pbz,一个非保留域的伪 email)。
    这类派生形**不是真实注入面**,R9(email 保留域)等 REDACT 级规则必须排除它们,
    否则会像引擎绝不会做的那样把伪 email 当真邮箱误报。
    """
    pool: list[str] = []
    seen: set[str] = set()
    rot13_forms: set[str] = set()

    def add(s: str | None):
        if s and s not in seen:
            seen.add(s)
            pool.append(s)

    for leaf in leaves:
        add(leaf)
        add(normalize_cn(leaf))
        # base64
        for m in _RE_B64.finditer(leaf):
            dec = try_b64(m.group(0))
            if dec and dec != m.group(0):
                add(dec)
        # hex
        for m in _RE_HEX.finditer(leaf):
            dec = try_hex(m.group(0))
            if dec and dec != m.group(0):
                add(dec)
        # rot13(对合)—— 加入 pool(供 BLOCK 级实体如 AKIA/PEM 独立复现),但登记为
        # rot13 派生形,好让 REDACT 级规则(R9)把它们排除在真实注入面之外。
        r = rot13(leaf)
        if r != leaf:
            add(r)
            rot13_forms.add(r)
    return pool, rot13_forms


# ── 结构性事实抽取(从整个 pool)─────────────────────────────────────────
def gather_facts(content, session_window: list[str] | None = None) -> dict:
    leaves = string_leaves(content)
    # 引擎语义(engine.py 第 74-75 行):session_window 以 "".join(window)+text 空串拼接
    # 后作为一个 session-window 变体,过完整 L0-L3.5。故校验器把每个原文叶子与 window
    # 前缀拼接后的串也纳入独立重算,否则会漏看被拆进历史消息的 AKIA/身份证(S5-04/05)。
    if session_window:
        prefix = "".join(session_window)
        leaves = list(leaves) + [prefix + leaf for leaf in string_leaves(content)]
    pool, rot13_forms = derived_texts(leaves)
    joined = "\n".join(pool)

    cn_ids = []
    for m in _RE_CN_ID.finditer(joined):
        s = m.group(0)
        cn_ids.append({"id": s, "mod11": cn_id_mod11(s), "should_be": cn_id_expected_check(s)})

    cards = []
    for m in _RE_DIGIT_RUN.finditer(joined):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19:
            cards.append({"raw": m.group(0).strip(), "digits": digits,
                          "luhn": luhn(digits), "test_card": digits in TEST_CARDS})

    aws_keys = []
    for m in _RE_AWS_AK.finditer(joined):
        tok = m.group(0)
        aws_keys.append({"key": tok, "official_example": tok in OFFICIAL_EXAMPLE_AWS_KEYS})

    gcp_keys = [m.group(0) for m in _RE_GCP_AK.finditer(joined)]

    # email 只在**非 rot13 派生**的池文本里抓:rot13 是对合变换,会把良性明文
    # 变造成非保留域伪 email(engine.py §4 收尾对 decoded:rot13 的 REDACT 级命中一律丢弃),
    # 那类伪 email 不是真实注入面,不能让 R9 当真邮箱误报(S2-02)。
    non_rot13_join = "\n".join(p for p in pool if p not in rot13_forms)
    emails = []
    for m in _RE_EMAIL.finditer(non_rot13_join):
        a = m.group(0)
        emails.append({"email": a, "reserved": is_reserved_domain_email(a)})

    pem = bool(re.search(r"-----BEGIN [A-Z0-9 ]*?PRIVATE KEY-----|-----BEGIN [A-Z ]+-----", joined))

    # 最高熵长 token(≥20 字符),供 L2 熵不变量参考
    top_entropy = 0.0
    top_tok = ""
    for leaf in leaves:  # 只在原文叶子上算,派生形会虚高
        for m in _RE_TOKEN.finditer(leaf):
            t = m.group(0)
            if len(t) >= 20:
                h = shannon_entropy(t)
                if h > top_entropy:
                    top_entropy, top_tok = h, t

    regex_defn = bool(_RE_REGEX_DEFN.search(joined))

    return {
        "cn_ids": cn_ids, "cards": cards, "aws_keys": aws_keys,
        "gcp_keys": gcp_keys, "emails": emails, "pem": pem,
        "top_entropy": top_entropy, "top_tok": top_tok,
        "regex_defn": regex_defn, "pool": pool, "joined": joined,
    }


# ── 对账规则:content 事实 × expected × invariants ───────────────────────
LAYER_OF_ENTITY = {
    "AWS_ACCESS_KEY": "L0", "AWS_SECRET_KEY": "L0", "GCP_API_KEY": "L0",
    "CN_ID_CARD": "L0", "CN_PHONE": "L0", "EMAIL": "L0",
}


def reconcile(fx: dict, facts: dict) -> tuple[list[str], list[str]]:
    """返回 (hard_flags, notes)。hard_flag=数学确定矛盾(致 exit 1);note=信息性。"""
    hard: list[str] = []
    notes: list[str] = []

    suite = fx.get("suite")
    exp = fx.get("expected", {}) or {}
    verdict = (exp.get("verdict") or "").lower()
    must_hit = exp.get("must_hit") or []
    must_not = exp.get("must_not_hit") or []
    invs = " ".join(fx.get("invariants") or [])
    mh_entities = {(h.get("entity") or "").upper() for h in must_hit}
    mh_actions = {(h.get("action") or "").lower() for h in must_hit}
    mn_entities = {(h.get("entity") or "").upper() for h in must_not}

    valid_ids = [c for c in facts["cn_ids"] if c["mod11"]]
    invalid_ids = [c for c in facts["cn_ids"] if not c["mod11"]]
    luhn_real_cards = [c for c in facts["cards"] if c["luhn"] and not c["test_card"]]
    real_aws = [k for k in facts["aws_keys"] if not k["official_example"]]
    reserved_emails = [e for e in facts["emails"] if e["reserved"]]
    real_emails = [e for e in facts["emails"] if not e["reserved"]]

    # R1: must_hit CN_ID_CARD ⟹ 必须有 mod-11 合法身份证
    if "CN_ID_CARD" in mh_entities and not valid_ids:
        detail = ""
        if invalid_ids:
            c = invalid_ids[0]
            detail = f"(content 有 {c['id']} 但 mod-11 不过,正确校验位应为 {c['should_be']})"
        hard.append(f"R1 must_hit CN_ID_CARD 但 content 无 mod-11 合法身份证{detail}"
                    f" → 引擎会正确不命中,harness 会误报为漏拦")

    # R2: invariants 声明 mod-11 通过/不过,与重算矛盾
    if re.search(r"mod-?11|身份证", invs):
        says_pass = bool(re.search(r"过\s*mod|mod-?11\s*(通过|过|valid|成立)|校验位(正确|通过|成立)", invs)) \
            and not re.search(r"不过|不通过|不成立|invalid|错误", invs)
        says_fail = bool(re.search(r"mod-?11\s*(不过|不通过|不成立|invalid)|不过\s*mod|校验位(错误|不通过|不成立)", invs))
        if says_pass and facts["cn_ids"] and not valid_ids:
            c = facts["cn_ids"][0]
            hard.append(f"R2 invariants 声称'过 mod-11'但 {c['id']} 实际不过(正确校验位 {c['should_be']})")
        if says_fail and valid_ids:
            hard.append(f"R2 invariants 声称'mod-11 不过'但 {valid_ids[0]['id']} 实际通过")

    # R3: must_hit CREDIT_CARD ⟹ 必须有 Luhn 合法非测试卡
    if "CREDIT_CARD" in mh_entities and not luhn_real_cards:
        why = ""
        if facts["cards"]:
            c = facts["cards"][0]
            why = f"(content 卡号 {c['digits']}: luhn={c['luhn']} test_card={c['test_card']})"
        hard.append(f"R3 must_hit CREDIT_CARD 但无 Luhn 合法非测试卡{why}")

    # R4(note): must_not_hit CREDIT_CARD 应因测试卡/Luhn不过/流水语境
    if "CREDIT_CARD" in mn_entities or (facts["cards"] and verdict == "pass"):
        serial_ctx = bool(re.search(r"流水|批次|序列|serial|batch|order|订单|运单|tracking",
                                    facts["joined"], re.IGNORECASE))
        for c in facts["cards"]:
            if c["luhn"] and not c["test_card"] and not serial_ctx:
                notes.append(f"R4 卡号 {c['digits']} Luhn 通过且非测试卡、无流水语境,"
                             f"但期望不命中/pass — 若非有意贴边,引擎可能会 REDACT(复核)")

    # R5: must_hit AWS_ACCESS_KEY ⟹ 必须有非官方示例的真 AKIA/ASIA
    if "AWS_ACCESS_KEY" in mh_entities:
        if not real_aws:
            hard.append("R5 must_hit AWS_ACCESS_KEY 但 content 无非官方示例的 AKIA/ASIA key")
        elif facts["regex_defn"]:
            notes.append("R5 content 含 AKIA 但呈'正则定义'外观(FP-10),引擎会抑制 — "
                         "若本例意在命中,须确认不是正则定义文本")

    # R6: must_not_hit AWS_ACCESS_KEY ⟹ 所有 AKIA 必须是官方示例值(否则引擎会 BLOCK→套件2 误报)
    if "AWS_ACCESS_KEY" in mn_entities and real_aws:
        if facts["regex_defn"]:
            notes.append(f"R6 声称 AKIA 不命中,token {real_aws[0]['key']} 非官方示例值,"
                         f"但内容像正则定义(FP-10)→ 引擎靠 _REGEX_DEFN 抑制(须确认该判据真能覆盖)")
        else:
            hard.append(f"R6 must_not_hit AWS_ACCESS_KEY 但 {real_aws[0]['key']} 非官方示例值、"
                        f"非正则定义 → 引擎会 BLOCK,套件2 将产生误报")

    # R7: base64/hex 解出目标不变量 —— 声明"解出 X"就验证 X 真的在解码结果里。
    # 边界字符集须排除【半角逗号】,否则中文 invariants("内藏 AKIA,引擎...")里 AKIA 后
    # 紧跟半角逗号时,target 会贪吃成 "AKIA,引擎解码后" 这类混合串,自然不在解码池 → 误报。
    m = re.search(r"(?:base64|hex|解出|decode[ds]?)[^\n]*?((?:https?://|AKIA|ASIA|AIza)[^\s'\"，,。;；]+)", invs)
    if m:
        target = m.group(1)
        if target not in facts["joined"]:
            hard.append(f"R7 invariants 声称解出 '{target}' 但独立 base64/hex 解码未产出该串")
        else:
            notes.append(f"R7 ✓ 解码目标 '{target}' 已独立复现")

    # R8: rot13 场景 —— 引擎 Fix A 只保 rot13 变体的 BLOCK 级命中,REDACT 级会被丢弃
    if suite == 3 and re.search(r"rot-?13", invs, re.IGNORECASE):
        r_forms = [rot13(l) for l in string_leaves(fx.get("content"))]
        r_join = "\n".join(r_forms)
        has_block_secret = bool(_RE_AWS_AK.search(r_join) or _RE_GCP_AK.search(r_join)
                                or re.search(r"-----BEGIN", r_join))
        redact_only = {"EMAIL", "CN_ID_CARD", "CN_PHONE"}
        if must_hit and mh_entities <= redact_only and not has_block_secret:
            hard.append("R8 rot13 变体仅藏 REDACT 级实体(email/身份证/手机),"
                        "引擎 Fix A 会丢弃 → 期望 must_hit 落空,应改为 verdict=pass")

    # R9: must_not_hit EMAIL / email+pass ⟹ 域名必须是 RFC2606 保留域(否则 FP-06 破功)
    email_should_pass = ("EMAIL" in mn_entities) or (facts["emails"] and verdict == "pass"
                                                     and "EMAIL" not in mh_entities)
    if email_should_pass and real_emails:
        hard.append(f"R9 期望 email 不命中,但 {real_emails[0]['email']} 非 RFC2606 保留域 → "
                    f"引擎会 REDACT,FP-06 破功")

    # R10: 套件6 verdict 恒 pass
    if suite == 6 and verdict != "pass":
        hard.append(f"R10 套件6 verdict 应恒为 pass(同步只验 L4 异步告警),实为 '{verdict}'")
    if suite == 6 and not exp.get("async_l4_category"):
        notes.append("R10 套件6 建议填 async_l4_category(proprietary-source/business-logic)")

    # R11(note): 套件4 纯通道级兜底口径。
    # 套件4 语义是"MCP/egress 注入点的内容扫描",绝大多数 block 由内容层实体决定
    # (AWS_ACCESS_KEY/GCP_API_KEY/PRIVATE_KEY/INTERNAL_DOMAIN 等,均为正确命中,不该期望
    # EGRESS_* 前缀)。只有当 verdict=block 却无任何内容层 must_hit 实体时,才可能是靠
    # egress.py 通道兜底(rule=egress_channel)—— 此时才提示复核通道管控口径。
    if suite == 4 and verdict == "block" and not must_hit:
        notes.append("R11 套件4 verdict=block 但 must_hit 为空 — 若靠通道兜底,复核 EGRESS 记录口径")

    # R12(note): 熵不变量参考值
    if re.search(r"熵|entropy", invs):
        if re.search(r"高|high", invs) and facts["top_entropy"] and facts["top_entropy"] < 4.0:
            notes.append(f"R12 invariants 称'熵高'但最高 token 熵仅 {facts['top_entropy']:.2f} bits/char(<4.0)")
        if re.search(r"低|low", invs) and facts["top_entropy"] >= 4.0:
            notes.append(f"R12 invariants 称'熵低'但存在熵 {facts['top_entropy']:.2f} bits/char 的 token")

    # R13: PEM 不变量 ⟹ content 必须真有 BEGIN 头
    if re.search(r"PEM|私钥|private\s*key|BEGIN", invs, re.IGNORECASE) and not facts["pem"]:
        hard.append("R13 invariants 提及 PEM/私钥 但 content 无 -----BEGIN ... KEY----- 头")

    # R14: verdict 与 must_hit action 的逻辑一致性(fixture 自身,独立于引擎)
    if "block" in mh_actions and verdict != "block":
        hard.append(f"R14 must_hit 含 block 级实体但 verdict='{verdict}'(应为 block)")
    elif "redact" in mh_actions and "block" not in mh_actions and verdict == "pass":
        hard.append("R14 must_hit 含 redact 级实体但 verdict=pass(应为 redact/block)")
    if not must_hit and verdict == "block" and suite != 4:
        notes.append("R14 verdict=block 但 must_hit 为空(非套件4 通道级)— 复核是否漏填断言")

    # R15(note): top_layer 与 must_hit 实体所属层的一致性(仅对无歧义的 L0 实体)
    top = (exp.get("top_layer") or "").upper().replace("L3.5", "L3.5")
    deciding_l0 = [e for e in mh_entities if LAYER_OF_ENTITY.get(e) == "L0"]
    if deciding_l0 and top and top not in ("L0",):
        # 有 L0 决定性实体却声明 top_layer 非 L0 —— 除非 L0 实体动作与 verdict 不符
        l0_decides = any((h.get("action") or "").lower() == verdict
                         for h in must_hit if (h.get("entity") or "").upper() in deciding_l0)
        if l0_decides:
            notes.append(f"R15 must_hit 含 L0 实体 {sorted(deciding_l0)} 且其动作=verdict,"
                         f"top_layer 通常应为 L0,实为 '{top}'(复核聚合)")

    return hard, notes


# ── 主流程 ────────────────────────────────────────────────────────────
def check_suite(suite: int) -> tuple[int, int, int, bool]:
    """返回 (case 数, hard_flag 数, note 数, 文件存在)。"""
    f = FIXTURE_DIR / f"suite{suite}.json"
    if not f.exists():
        return 0, 0, 0, False
    try:
        cases = json.loads(f.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        print(f"  ✗ suite{suite}.json 读取失败: {e}")
        return 0, 1, 0, True

    hard_total = note_total = 0
    print(f"\n══ 套件{suite} ({len(cases)} 例) ══")
    for fx in cases:
        cid = fx.get("id", "?")
        try:
            facts = gather_facts(fx.get("content"), fx.get("session_window"))
            hard, notes = reconcile(fx, facts)
        except Exception as e:  # noqa: BLE001 — 校验器自身不得因单条崩溃中断全局
            print(f"  ✗ {cid}: 校验器内部异常 {type(e).__name__}: {e}")
            hard_total += 1
            continue
        if not hard and not notes:
            print(f"  ✓ {cid}")
        else:
            for h in hard:
                print(f"  ✗ {cid}: {h}")
            for n in notes:
                print(f"  · {cid}: {n}")
        hard_total += len(hard)
        note_total += len(notes)
    return len(cases), hard_total, note_total, True


def main(argv: list[str]) -> int:
    only = None
    if "--suite" in argv:
        only = int(argv[argv.index("--suite") + 1])

    suites = [only] if only else [1, 2, 3, 4, 5, 6]
    present = [s for s in suites if (FIXTURE_DIR / f"suite{s}.json").exists()]
    if not present:
        print("fixtures 尚未生成(tests/fixtures/suite*.json 全缺)——待后台 agent 完成后再跑。")
        print("契约已就绪:落地即可 `python3 -m tests.fixture_invariants_check`。")
        return 0

    grand_cases = grand_hard = grand_note = 0
    for s in suites:
        n, h, note, exists = check_suite(s)
        grand_cases += n
        grand_hard += h
        grand_note += note

    print(f"\n{'='*56}")
    print(f"总计:{grand_cases} 例 | 硬矛盾 {grand_hard} | 提示 {grand_note}")
    if grand_hard:
        print("✗ 存在 fixture 内部矛盾 —— 跑矩阵前必须先修 fixture,否则会误判为引擎缺陷。")
    else:
        print("✓ 无硬矛盾:所有 fixture 的 content 结构上都能支撑其 expected 声明。")
    return 1 if grand_hard else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
