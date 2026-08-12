#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
"""L3 Presidio(SPEC §5-L3)—— ≤100ms/100token,同步。

调官方 analyzer 容器 HTTP :5002/analyze。中文识别器 + Luhn 信用卡。
不可达时 **fail-closed 或告警,绝不静默 pass** —— 返回 (hits, status)
让引擎能区分"真 PASS"与"L3 缺席"。
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request

from .l0_regex import is_reserved_email
from .types import Hit, Layer, Verdict

# 容器内由 compose 注入 PRESIDIO_ANALYZER_URL;默认对齐 SPEC §9 的服务名:端口。
ANALYZER_URL = os.environ.get("PRESIDIO_ANALYZER_URL", "http://presidio-analyzer:5002/analyze")

# 实体→action
_ENTITY_ACTION = {
    "PERSON": Verdict.REDACT,
    "EMAIL_ADDRESS": Verdict.REDACT,
    "PHONE_NUMBER": Verdict.REDACT,
    "LOCATION": Verdict.REDACT,
    "CREDIT_CARD": Verdict.REDACT,
    "IP_ADDRESS": Verdict.REDACT,
    "IBAN_CODE": Verdict.REDACT,
    "CN_ID": Verdict.REDACT,
}

# 测试卡号白名单(FP-08)
_TEST_CARDS = {"4111111111111111", "5555555555554444", "378282246310005",
               "4242424242424242", "5105105105105100"}
# 流水号/批次号语境 → 把 CREDIT_CARD 置信度降到阈值下(L3-11)
_SERIAL_CTX = re.compile(r"(流水|批次|序列|serial|batch|order|订单|运单|tracking)", re.IGNORECASE)
# 公开人名/泛指地名降权(FP-07)
_PUBLIC_NAMES = {"salvatore", "guido", "linus", "guido van rossum"}

# 弱 NER 实体:来自 spaCy 统计模型,Presidio 对其恒给 0.85 分(分数不携带真实置信度,
# 阈值无法区分真假)。区别于模式类实体(EMAIL/PHONE/CREDIT_CARD/IP/IBAN/CN_ID:
# 正则+校验和+上下文,可独立裁决)。实例实测(2026-07-30 套件2/6):en 模型把整句中文
# 标 PERSON、zh 模型把 hex 片段/英文单词标 PERSON/LOCATION,均 0.85 分。
# 处置:①合法性过滤(_ner_plausible)剔除明显碎片;②同一次扫描内须有模式类强实体
# 佐证,弱 NER 才参与同步裁决——单独弱实体交 L4 异步语义层,不产同步 REDACT。
# 语料契约:56 条 fixture 无一 must_hit 要求 PERSON/LOCATION(S2-13 反而 must_not_hit
# PERSON);03 文档 L3-09 的 redact 语义是"PERSON+EMAIL+PHONE 多实体组合"。
_NER_WEAK = {"PERSON", "LOCATION"}
_CJK = re.compile(r"[一-鿿]")
_NER_PUNCT = re.compile(r"[,。;;!?::、,!?/@=]")

_SCORE_THRESHOLD = 0.5


def _ner_plausible(frag: str, lang: str) -> bool:
    """弱 NER 片段是否像一个真实人名/地名(而非被误标的从句/编码碎片)。"""
    f = frag.strip()
    if not f:
        return False
    if any(ch.isdigit() for ch in f):
        return False  # hex/base64/UUID/门牌号碎片,真名字不含数字
    if _NER_PUNCT.search(f):
        return False  # 含句读/符号 → 整句或从句被误标
    cjk = len(_CJK.findall(f))
    if lang == "en" and cjk:
        return False  # en 模型无中文 NER 能力,含 CJK 的命中一律不可信
    return len(f) <= (10 if cjk else 26)  # 中文名≤10 字,拉丁全名≤26 字符


def _luhn(num: str) -> bool:
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


def _call_analyzer(text: str, language: str = "en", timeout: float = 2.0) -> list[dict]:
    payload = json.dumps({"text": text, "language": language}).encode("utf-8")
    req = urllib.request.Request(
        ANALYZER_URL, data=payload,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def scan(text: str, source: str = "normalized", languages=("en", "zh")) -> tuple[list[Hit], str]:
    """返回 (hits, status)。status ∈ {"ok","partial","unreachable"}。

    - ok:所有请求语言的识别器都成功返回 → 结果完整可信。
    - partial:**部分**语言成功、部分失败(网络抖动 / 单语言识别器抽风 / 坏响应)
      → analyzer 在线但覆盖有缺口,失败语言的 PII 可能漏检。**绝不能**因另一语言成功
      就把整体当 "ok"(D3:否则 zh 挂 / en 通 时中文 PII 被静默漏掉)。
    - unreachable:所有语言都失败 → analyzer 完全掉线,fail-closed。
    坏 JSON / 非法响应(ValueError)与网络不可达一样,记为该语言失败——不当"扫过且干净"(G3)。
    """
    raw: list[tuple[str, dict]] = []  # (lang, 识别结果) —— 弱 NER 合法性判定需要来源语言
    ok_langs: list[str] = []
    failed_langs: list[str] = []
    for lang in languages:
        try:
            raw.extend((lang, r) for r in _call_analyzer(text, lang))
            ok_langs.append(lang)
        except (urllib.error.URLError, OSError, ValueError, TimeoutError):
            # 网络不可达 / 超时 / 坏 JSON(json.JSONDecodeError ⊂ ValueError)——均记为该语言缺席
            failed_langs.append(lang)
    if not ok_langs:
        # fail-closed 语义:不产 PASS,交由引擎按"L3 缺席"标注
        return [], "unreachable"

    hits: list[Hit] = []
    weak_pending: list[Hit] = []  # 合法但无佐证的弱 NER,凑齐强实体才转正
    has_strong = False
    serial_ctx = bool(_SERIAL_CTX.search(text))
    for lang, r in raw:
        entity = r.get("entity_type", "")
        score = float(r.get("score", 0.0))
        start, end = int(r.get("start", -1)), int(r.get("end", -1))
        frag = text[start:end] if start >= 0 else ""

        if entity == "CREDIT_CARD":
            digits = re.sub(r"\D", "", frag)
            if digits in _TEST_CARDS:
                continue  # 测试卡号(FP-08)
            if not _luhn(digits):
                continue  # Luhn 不过 → 非真卡号
            if serial_ctx:
                # 流水号语境降权(L3-11):语义是"压到阈值下"。Presidio 对 Luhn 全过的
                # 16 位数给满分 1.0,固定减 0.4 只剩 0.6 仍越阈(S2-14 实测误报),
                # 故直接钳到阈值之下。
                score = min(score, _SCORE_THRESHOLD - 0.1)
        if entity == "PERSON" and frag.strip().lower() in _PUBLIC_NAMES:
            continue  # 公开作者真名不同步 redact(FP-07)
        if entity == "EMAIL_ADDRESS" and is_reserved_email(frag):
            continue  # RFC2606 保留域名邮箱豁免(FP-06)——与 L0 复用同一白名单,防两处漂移

        action = _ENTITY_ACTION.get(entity)
        if action is None or score < _SCORE_THRESHOLD:
            continue
        h = Hit(Layer.L3, f"presidio:{entity.lower()}", entity,
                (start, end), frag, action, confidence=score, source=source)
        if entity in _NER_WEAK:
            if not _ner_plausible(frag, lang):
                continue  # 碎片/整句误标,直接丢
            weak_pending.append(h)
        else:
            has_strong = True
            hits.append(h)
    # 弱 NER 单独出现不产同步 REDACT(交 L4 异步语义);有模式类强实体佐证才转正——
    # 保 L3-09"多实体组合 redact"语义,灭套件2/6 里"整句当人名"型误伤。
    if has_strong:
        hits.extend(weak_pending)
    # 有语言失败但非全失败 → partial:命中的 hits 可信,但失败语言的 PII 可能漏,引擎须标注 L3 缺席。
    return hits, ("partial" if failed_langs else "ok")
