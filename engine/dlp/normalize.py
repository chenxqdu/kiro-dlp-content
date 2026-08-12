#
# Copyright (c) 2026 Amazon.com and Affiliates.
# SPDX-License-Identifier: Apache-2.0
#
"""归一化预处理(SPEC §4)—— 套件3(编码/拆分/混淆规避)的命根子。

铁律:**先扫原文,再扫每个变体**。变体命中时 hit.source 必须标明来源。
本模块只负责"产出回扫变体列表",不做命中判定。
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata

# 零宽 / 不可见连接符
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍﻿⁠᠎"), None)

# 中文数字 → 阿拉伯(身份证/手机场景,EVA-11)
_CN_DIGITS = str.maketrans("零一二三四五六七八九〇", "01234567890")


def normalize(text: str) -> str:
    """NFKC + 去零宽 + 中文数字→阿拉伯。

    注意:这里**不**做去分隔符(那会破坏正常文本语义),
    去分隔符由 strip_separators() 单独产出一条候选变体,在 expand() 里并列回扫。
    """
    t = unicodedata.normalize("NFKC", text)
    t = t.translate(_ZERO_WIDTH)
    t = t.translate(_CN_DIGITS)
    return t


# 疑似连续 token 的分隔符混淆(仅在候选 token 内部剥离,见 strip_separators)
_SEP_CHARS = re.compile(r"[-_\s.]")
# "疑似 token" = 由字母数字与分隔符组成、去分隔符后长度>=12 的串
_TOKEN_CANDIDATE = re.compile(r"[A-Za-z0-9][A-Za-z0-9\-_\s.]{10,}[A-Za-z0-9]")


def strip_separators(text: str) -> str:
    """把文本中每个"疑似 token"内部的分隔符去掉,产出一条候选变体。

    例:'AKIA-IOSF ODNN.7EXA_MPLE' → 该 token 内分隔符剥离 → 'AKIAIOSFODNN7EXAMPLE'。
    非 token 区域(正常英文/中文)保持原样,避免把普通句子挤成一坨。
    """
    def _strip(m: re.Match) -> str:
        return _SEP_CHARS.sub("", m.group(0))

    return _TOKEN_CANDIDATE.sub(_strip, text)


# ---- 可逆编码解码(EVA-01/02/17)----

_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
_PRINTABLE = re.compile(rb"^[\x09\x0a\x0d\x20-\x7e]+$")


def _try_b64(s: str) -> str | None:
    # base64 长度必须是 4 的倍数才尝试(容错:补 =)
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


def _try_hex(s: str) -> str | None:
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


def decode_variants(text: str) -> list[tuple[str, str]]:
    """对文本中的可疑片段尝试 base64 / hex / rot13 解码。

    返回 [(变体文本, 类型标签), ...],类型标签 ∈ {"base64","hex","rot13"} ——
    §4 铁律要求命中能标明来源,故按解码类型**分开**产出变体(而非合并成一条),
    这样引擎能把每条 hit 的 source 精确记为 decoded:base64 / decoded:hex / decoded:rot13。
    解不出或解出乱码 → 丢弃(不产生噪声)。
    每条变体是"原文 + 解出片段"的拼接,以便解出的 key 与其上下文一起被 L0/L1 命中。
    """
    variants: list[tuple[str, str]] = []

    b64_frags: list[str] = []
    for m in _B64_RE.finditer(text):
        dec = _try_b64(m.group(0))
        if dec and dec != m.group(0):
            b64_frags.append(dec)
    if b64_frags:
        variants.append((text + " " + " ".join(b64_frags), "base64"))

    hex_frags: list[str] = []
    for m in _HEX_RE.finditer(text):
        dec = _try_hex(m.group(0))
        if dec and dec != m.group(0):
            hex_frags.append(dec)
    if hex_frags:
        variants.append((text + " " + " ".join(hex_frags), "hex"))

    # rot13:整体解一遍(只有当解出结果含大写连续串时才可能有意义,但无害,统一产出)
    rot = codecs.encode(text, "rot13")
    if rot != text:
        variants.append((rot, "rot13"))

    return variants


def fold_concat(text: str) -> str | None:
    """常量折叠:相邻字符串字面量 / 变量拼接(EVA-04/18)。

    识别形如  "AKIA"+"IOSFO"+"DNN7"+"EXAMPLE"  或  "A" "B"  的相邻字面量,
    以及  part1='AKIAIOSFO';part2='DNN7EXAMPLE';full=part1+part2  的同段变量拼接。
    返回折叠后追加了拼接结果的文本;无可折叠返回 None。
    """
    folded_pieces: list[str] = []

    # 1) 相邻字符串字面量拼接: "a"+"b" 或 "a" "b"
    lit = r'''["']([^"']*)["']'''
    concat = re.compile(rf'{lit}(?:\s*\+\s*|\s+){lit}')
    # 迭代折叠多段
    working = text
    changed = True
    joined_literals: list[str] = []
    while changed:
        changed = False
        def _join(m: re.Match) -> str:
            return '"' + m.group(1) + m.group(2) + '"'
        new = concat.sub(_join, working)
        if new != working:
            working = new
            changed = True
    # 抽出折叠后的长字面量
    for m in re.finditer(lit, working):
        if len(m.group(1)) >= 12:
            joined_literals.append(m.group(1))

    # 2) 变量赋值 + 拼接: part1='..';part2='..';full=part1+part2
    assigns = dict(re.findall(r'''(\w+)\s*=\s*["']([^"']*)["']''', text))
    for m in re.finditer(r'(\w+)\s*=\s*(\w+)\s*\+\s*(\w+)', text):
        a, b = m.group(2), m.group(3)
        if a in assigns and b in assigns:
            folded_pieces.append(assigns[a] + assigns[b])

    folded_pieces.extend(joined_literals)
    if folded_pieces:
        return text + " " + " ".join(folded_pieces)
    return None


def expand(text: str, session_window: list[str] | None = None) -> list[str]:
    """产出全部回扫变体(去重,保序):
      [原文, 归一化, 去分隔符, 解码变体..., 折叠拼接, 跨消息拼接]
    """
    out: list[str] = []
    seen: set[str] = set()

    def _add(s: str | None):
        if s and s not in seen:
            seen.add(s)
            out.append(s)

    _add(text)
    norm = normalize(text)
    _add(norm)
    _add(strip_separators(norm))
    for v, _kind in decode_variants(norm):  # expand() 只需变体文本,类型标签在 engine 侧用于标 source
        _add(v)
    _add(fold_concat(norm))

    # 跨消息滑窗拼接(EVA-03):历史片段 + 当前文本 → 一条候选
    if session_window:
        joined = "".join(session_window) + text
        _add(normalize(joined))
        _add(strip_separators(normalize(joined)))

    return out
