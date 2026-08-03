#!/usr/bin/env python3
"""生成 56 条 fixture(suite1..6)—— 03 文档 §4 测试矩阵。

设计原则(为何这样写,而非脑推 JSON):
  1. 合成敏感值必须**数学正确**(mod-11 身份证 / Luhn 卡 / AKIA 结构 / GCP 39 长),
     且**避开**引擎白名单(官方示例 AKIAIOSFODNN7EXAMPLE、5 张测试卡),否则被静默放行,
     或与 fixture_invariants_check.py 的 R3/R5/R8 硬冲突。本脚本用独立算法合成并 assert 自检。
  2. `expected` 用引擎**真实行为**校准:本脚本对每条 case 本机实跑 engine.scan(),
     - 本机可终判层(L0/L1/L2/L3.5,不依赖 Presidio):expected 必须 == 实跑,否则报错退出。
     - 依赖 L3/Presidio 的 case(信用卡 / 中文人名 / 地名 / IP):本机 analyzer 缺席,
       标 needs_l3=True;本机走 run_offline 的"L3 缺席豁免",终判留实例(:5002 在线)复跑。
  3. 三处硬冲突已在数据里消解:
     - BLOCK 类一律用合成非官方 AKIA/GCP/secret;AKIAIOSFODNN7EXAMPLE 仅用于 suite2 白名单-pass。
     - 信用卡 redact 用合成非测试 Luhn 卡。
     - suite3 rot13 变体:engine 收尾只保 BLOCK 级(AKIA/GCP/PEM),藏 REDACT 级则 verdict=pass。

用法:
  python3 tests/gen_fixtures.py            # 生成 + 本机三角对账(L3 依赖项跳过终判)
  python3 tests/gen_fixtures.py --check    # 只对账不写文件
"""
from __future__ import annotations

import argparse
import base64
import codecs
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
FIXture_DIR = _ROOT / "tests" / "fixtures"

# ───────────────────────── 合成敏感值(独立算法 + 自检)─────────────────────────

def _cn_id_check(body17: str) -> str:
    w = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    c = "10X98765432"
    return c[sum(int(body17[i]) * w[i] for i in range(17)) % 11]

def make_cnid(body17: str) -> str:
    assert len(body17) == 17 and body17.isdigit()
    return body17 + _cn_id_check(body17)

def _luhn_ok(num: str) -> bool:
    d = [int(x) for x in num]
    par = len(d) % 2
    t = 0
    for i, x in enumerate(d):
        if i % 2 == par:
            x *= 2
            if x > 9:
                x -= 9
        t += x
    return t % 10 == 0

def make_luhn(body_prefix: str, length: int = 16) -> str:
    body = body_prefix
    fill = "1234567890"
    while len(body) < length - 1:
        body += fill[len(body) % 10]
    for cd in "0123456789":
        if _luhn_ok(body + cd):
            return body + cd
    raise RuntimeError("no luhn digit")

TEST_CARDS = {"4111111111111111", "5555555555554444", "378282246310005",
              "4242424242424242", "5105105105105100"}
OFFICIAL_AKIA = "AKIAIOSFODNN7EXAMPLE"

# 合成值
CNID_1 = make_cnid("11010119900307001")   # 北京
CNID_2 = make_cnid("31010119851201223")   # 上海
CNID_3 = make_cnid("44030120011115088")   # 深圳
CARD_VISA = make_luhn("453912345678", 16)     # Visa,非测试卡
CARD_MC = make_luhn("541200009999", 16)       # MasterCard,非测试卡
AKIA_1 = "AKIA" + "TESTKEY1234567XY"          # 合成非官方,20 长
AKIA_2 = "AKIA" + "J5ROTATE9WQ8Z7TP"          # 合成非官方
ASIA_1 = "ASIA" + "TMPCRED567KLMNPQ"          # STS 临时凭证前缀
GCP_1 = "AIza" + "A" * 35                     # 39 长,走 L0 gcp_api_key
AWS_SK = "aB3dE6gH9jK2mN5pQ8rS1tU4vW7xY0zC3eF6iL9o"  # 40 [A-Za-z0-9/+]
L2_TOKEN = "Xq7Kp2Lm9Rn4Ts6Vw8Yz1Bc3Df5Gh0Jk2Mp4Qr"  # 纯高熵 → L2 GENERIC_SECRET
PEM = ("-----BEGIN RSA PRIVATE KEY-----\n"
       "MIIEowIBAAKCAQEArandomBase64Body123456789abcdefGHIJKLMNOP\n"
       "-----END RSA PRIVATE KEY-----")

# —— 合成值自检(数学正确性 + 避白名单)——
def _self_check() -> None:
    assert _cn_id_check(CNID_1[:17]) == CNID_1[17], "CNID_1 mod11"
    assert all(len(x) == 18 for x in (CNID_1, CNID_2, CNID_3))
    assert _luhn_ok(CARD_VISA) and CARD_VISA not in TEST_CARDS, "VISA"
    assert _luhn_ok(CARD_MC) and CARD_MC not in TEST_CARDS, "MC"
    for a in (AKIA_1, AKIA_2, ASIA_1):
        assert len(a) == 20 and a[:4] in ("AKIA", "ASIA") and a[4:].isalnum() and a[4:].isupper()
        assert a != OFFICIAL_AKIA, "must not be official example"
    assert len(GCP_1) == 39 and GCP_1.startswith("AIza")
    assert len(AWS_SK) == 40
    assert "BEGIN RSA PRIVATE KEY" in PEM

def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()

def hexs(s: str) -> str:
    return s.encode().hex()

def rot13(s: str) -> str:
    return codecs.encode(s, "rot13")

# ───────────────────────── 套件定义 ─────────────────────────
# 每条:(id, injection_point, content, content_kind, session_window,
#         expected{...}, invariants[], verify_point, notes_expected[])
# expected.top_layer 用引擎聚合口径;must_hit/must_not_hit 用 {entity,action}。
# needs_l3=True 的 case 依赖 Presidio(本机缺席),本机对账跳过终判。

def P(entity, action):
    return {"entity": entity, "action": action}

# ========== SUITE 1:真阳性拦截(应 BLOCK / REDACT)11 条 ==========
SUITE1 = [
    dict(id="S1-01", injection_point="prompt",
         content=f"部署脚本里写死了 {AKIA_1},请帮我改成读环境变量。",
         expected=dict(verdict="block", top_layer="L0",
                       must_hit=[P("AWS_ACCESS_KEY", "block")], must_not_hit=[]),
         invariants=["AKIA 为合成非官方示例 key,结构合法(AKIA+16 大写字母数字)"],
         verify_point="L0 正则命中 AWS AK → BLOCK,请求不出网关"),
    dict(id="S1-02", injection_point="prompt",
         content=f"临时凭证 {ASIA_1} 有效期两小时,先用着。",
         expected=dict(verdict="block", top_layer="L0",
                       must_hit=[P("AWS_ACCESS_KEY", "block")], must_not_hit=[]),
         invariants=["ASIA 前缀=STS 临时凭证,同 aws_access_key 规则"],
         verify_point="STS 临时凭证前缀也走 aws_access_key BLOCK"),
    dict(id="S1-03", injection_point="prompt",
         content=f"我们的 GCP key 是 {GCP_1},调用地图 API 用。",
         expected=dict(verdict="block", top_layer="L0",
                       must_hit=[P("GCP_API_KEY", "block")], must_not_hit=[]),
         invariants=["GCP key = AIza+35,共 39 字符,走 L0 gcp_api_key"],
         verify_point="L0 GCP API key BLOCK"),
    dict(id="S1-04", injection_point="prompt",
         content=f"配置项 aws_secret_access_key = {AWS_SK}",
         expected=dict(verdict="block", top_layer="L0",
                       must_hit=[P("AWS_SECRET_KEY", "block")], must_not_hit=[]),
         invariants=["40 字符 secret + 语境词 aws_secret_access_key → L0 aws_secret_key"],
         verify_point="L0 AWS secret key(需语境)BLOCK"),
    dict(id="S1-05", injection_point="prompt",
         content=f"这是我们的服务私钥,请解析:\n{PEM}",
         expected=dict(verdict="block", top_layer="L1",
                       must_hit=[P("PRIVATE_KEY", "block")], must_not_hit=[]),
         invariants=["PEM 含 BEGIN RSA PRIVATE KEY 头 → L1 签名"],
         verify_point="L1 PEM 私钥 BLOCK"),
    dict(id="S1-06", injection_point="prompt",
         content=f"internal service token: {L2_TOKEN}",
         expected=dict(verdict="block", top_layer="L2",
                       must_hit=[P("GENERIC_SECRET", "block")], must_not_hit=[]),
         invariants=["40 字符高熵无已知前缀,且窗口内有英文密钥语境词(token)→ L2 熵检测",
                     "L2 语境词表仅英文(secret/token/api_key/access_key…),纯中文语境不触发"],
         verify_point="L2 高熵通用密钥 BLOCK(需英文赋值/密钥语境词)"),
    dict(id="S1-07", injection_point="prompt",
         content="我们在推进 Project Nightingale,请评审架构。",
         expected=dict(verdict="block", top_layer="L3.5",
                       must_hit=[P("PROPRIETARY_TERM", "block")], must_not_hit=[]),
         invariants=["术语表内置代号 Project Nightingale(大小写敏感)"],
         verify_point="L3.5 术语表专有代号 BLOCK"),
    dict(id="S1-08", injection_point="prompt",
         content="回源到 api.corp.example.net 拉取配置文件。",
         expected=dict(verdict="block", top_layer="L3.5",
                       must_hit=[P("INTERNAL_DOMAIN", "block")], must_not_hit=[]),
         invariants=["内部域名 *.corp.example.net → L3.5 corp_domain"],
         verify_point="L3.5 内部域名 BLOCK"),
    dict(id="S1-09", injection_point="prompt",
         content=f"用户身份证 {CNID_1},请登记。",
         expected=dict(verdict="redact", top_layer="L0",
                       must_hit=[P("CN_ID_CARD", "redact")], must_not_hit=[]),
         invariants=["mod-11 合法身份证 → L0 REDACT"],
         verify_point="L0 中国身份证 REDACT(脱敏放行,非拦截)"),
    dict(id="S1-10", injection_point="prompt",
         content=f"客户手机 13812345678,身份证 {CNID_2},请回访。",
         expected=dict(verdict="redact", top_layer="L0",
                       must_hit=[P("CN_PHONE", "redact"), P("CN_ID_CARD", "redact")],
                       must_not_hit=[]),
         invariants=["手机号与身份证同现,均 REDACT"],
         verify_point="L0 手机+身份证双 REDACT"),
    dict(id="S1-11", injection_point="prompt",
         content="关联工单 SEV2-12345,请跟进处理进度。",
         expected=dict(verdict="redact", top_layer="L3.5",
                       must_hit=[P("PROPRIETARY_TERM", "redact")], must_not_hit=[]),
         invariants=["工单号 SEV\\d-\\d{3,6} → L3.5 REDACT"],
         verify_point="L3.5 工单号 REDACT"),
]

# ========== SUITE 2:误报防御(全须 PASS)16 条 ==========
# 每条都是"长得像敏感但不是"的干净值;引擎任一层误命中即算 FP。
SUITE2 = [
    dict(id="S2-01", injection_point="prompt",
         content=f"官方文档里给出的占位串 {OFFICIAL_AKIA},照抄即可。",
         expected=dict(verdict="pass", top_layer=None, must_hit=[],
                       must_not_hit=[P("AWS_ACCESS_KEY", "block"),
                                     P("GENERIC_SECRET", "block")]),
         invariants=["官方示例 AKIAIOSFODNN7EXAMPLE 在 L0 白名单 → 放行",
                     "文案不含英文密钥语境词,避免 L2 把该串当高熵通用密钥误判"],
         verify_point="白名单:官方示例 AK 不误拦(且不落 L2)"),
    dict(id="S2-02", injection_point="prompt",
         content="联系邮箱 support@example.com,有问题发这里。",
         expected=dict(verdict="pass", top_layer=None, must_hit=[],
                       must_not_hit=[P("EMAIL", "redact")]),
         invariants=["example.com 保留域 → L0 is_reserved_email 豁免,不脱敏",
                     "L0 邮箱 entity 命名为 EMAIL(与 L3/Presidio 的 EMAIL_ADDRESS 区分)"],
         verify_point="保留域邮箱不误脱敏"),
    dict(id="S2-03", injection_point="prompt",
         content="测试站点 https://foo.test 与 bar.example 均为占位域名。",
         expected=dict(verdict="pass", top_layer=None, must_hit=[], must_not_hit=[]),
         invariants=[".test/.example 保留 TLD → 不当内部域名"],
         verify_point="保留 TLD 不误判内部域名"),
    dict(id="S2-04", injection_point="prompt",
         content="AWS AK 的正则是 AKIA[0-9A-Z]{16},请写进文档。",
         expected=dict(verdict="pass", top_layer=None, must_hit=[],
                       must_not_hit=[P("AWS_ACCESS_KEY", "block")]),
         invariants=["正则定义串 AKIA[0-9A-Z]{16} 非真实 key"],
         verify_point="正则/模式定义不误拦"),
    dict(id="S2-05", injection_point="prompt",
         content="请求 ID 为 550e8400-e29b-41d4-a716-446655440000,查一下日志。",
         expected=dict(verdict="pass", top_layer=None, must_hit=[],
                       must_not_hit=[P("GENERIC_SECRET", "block")]),
         invariants=["UUID 低熵结构化 → 不当高熵密钥"],
         verify_point="UUID 不误判密钥"),
    dict(id="S2-06", injection_point="prompt",
         content="提交哈希 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08,已合入。",
         expected=dict(verdict="pass", top_layer=None, must_hit=[], must_not_hit=[]),
         invariants=["git/sha256 十六进制摘要 → 非密钥"],
         verify_point="commit/sha 摘要不误拦"),
    dict(id="S2-07", injection_point="prompt",
         content="占位串 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 用于填充。",
         expected=dict(verdict="pass", top_layer=None, must_hit=[],
                       must_not_hit=[P("GENERIC_SECRET", "block")]),
         invariants=["低熵重复串 → 熵不足,不触 L2"],
         verify_point="低熵重复串不误判密钥"),
    dict(id="S2-08", injection_point="prompt",
         content="Base64 示例 VGhlIHF1aWNrIGZveA== 解码是一句英文。",
         expected=dict(verdict="pass", top_layer=None, must_hit=[], must_not_hit=[]),
         invariants=["短 base64 解码=普通文本,无嵌套敏感"],
         verify_point="短 base64 干净值不误拦"),
    dict(id="S2-09", injection_point="prompt",
         content="主题色用 #1A2B3C,悬停 #FF8800。",
         expected=dict(verdict="pass", top_layer=None, must_hit=[], must_not_hit=[]),
         invariants=["hex 颜色码 → 非密钥"],
         verify_point="hex 颜色不误拦"),
    dict(id="S2-10", injection_point="prompt",
         content="文件 md5 为 d41d8cd98f00b204e9800998ecf8427e,校验一致。",
         expected=dict(verdict="pass", top_layer=None, must_hit=[], must_not_hit=[]),
         invariants=["md5 十六进制 → 非密钥"],
         verify_point="md5 摘要不误拦"),
    dict(id="S2-11", injection_point="prompt",
         content="当前版本 v2.14.3-rc.1,下周发布。",
         expected=dict(verdict="pass", top_layer=None, must_hit=[], must_not_hit=[]),
         invariants=["语义化版本号 → 非敏感"],
         verify_point="版本号不误拦"),
    dict(id="S2-12", injection_point="prompt",
         content="用测试卡 4111111111111111 走一笔沙箱支付。",
         expected=dict(verdict="pass", top_layer=None, must_hit=[],
                       must_not_hit=[P("CREDIT_CARD", "redact")]),
         invariants=["4111 是公开测试卡,L3 白名单 → 不脱敏", "needs_l3:实例复判"],
         verify_point="测试卡不误脱敏", needs_l3=True),
    dict(id="S2-13", injection_point="prompt",
         content="感谢 Guido 对语言设计的贡献。",
         expected=dict(verdict="pass", top_layer=None, must_hit=[],
                       must_not_hit=[P("PERSON", "redact")]),
         invariants=["公开人物名 guido 在 L3 白名单", "needs_l3:实例复判"],
         verify_point="公开人名不误脱敏", needs_l3=True),
    dict(id="S2-14", injection_point="prompt",
         content=f"物流运单号 {CARD_VISA},请查询签收状态。",
         expected=dict(verdict="pass", top_layer=None, must_hit=[],
                       must_not_hit=[P("CREDIT_CARD", "redact")]),
         invariants=["运单/流水语境 → CREDIT_CARD 降权 <0.5,不脱敏", "needs_l3:实例复判"],
         verify_point="流水号语境下 16 位数字不误判信用卡", needs_l3=True),
    dict(id="S2-15", injection_point="prompt",
         content="裸代号 falcon 只是内部昵称,无上下文。",
         expected=dict(verdict="pass", top_layer=None, must_hit=[],
                       must_not_hit=[P("PROPRIETARY_TERM", "block")]),
         invariants=["falcon 需 project/内部/codename 语境才 BLOCK,裸词放行"],
         verify_point="歧义代号无语境不误拦"),
    dict(id="S2-16", injection_point="prompt",
         content="小写 project nightingale 不是我们的正式代号写法。",
         expected=dict(verdict="pass", top_layer=None, must_hit=[],
                       must_not_hit=[P("PROPRIETARY_TERM", "block")]),
         invariants=["术语大小写敏感,小写变体不命中"],
         verify_point="大小写敏感术语的小写不误拦"),
]

# —— 规避手法 helper ——
_CN_DIGITS = {"0": "〇", "1": "一", "2": "二", "3": "三", "4": "四",
              "5": "五", "6": "六", "7": "七", "8": "八", "9": "九"}

def to_cn_digits(s: str) -> str:
    """阿拉伯数字 → 中文数字(normalize 应还原);非数字原样保留(如身份证尾 X)。"""
    return "".join(_CN_DIGITS.get(ch, ch) for ch in s)

def zwsp(s: str) -> str:
    """在每个字符间插入零宽空格 U+200B(normalize 应剥离)。"""
    return "​".join(s)

# ========== SUITE 3:对抗 / 规避(编码、零宽、normalize)10 条 ==========
# 铁律:rot13 变体只藏 BLOCK 级密钥(engine 收尾丢弃 rot13 里的 REDACT 级)。
SUITE3 = [
    dict(id="S3-01", injection_point="prompt",
         content=f"这段 base64 你先解一下:{b64(AKIA_2)},看看是什么。",
         expected=dict(verdict="block", top_layer="L0",
                       must_hit=[P("AWS_ACCESS_KEY", "block")], must_not_hit=[]),
         invariants=["base64 内藏 AKIA,引擎解码后 L0 命中(source=decoded)"],
         verify_point="base64 编码规避:解码后仍拦 AWS AK"),
    dict(id="S3-02", injection_point="prompt",
         content=f"十六进制串:{hexs(AKIA_2)}",
         expected=dict(verdict="block", top_layer="L0",
                       must_hit=[P("AWS_ACCESS_KEY", "block")], must_not_hit=[]),
         invariants=["hex 内藏 AKIA,解码后命中"],
         verify_point="hex 编码规避:解码后仍拦"),
    dict(id="S3-03", injection_point="prompt",
         content=f"rot13 一下:{rot13(AKIA_2)}",
         expected=dict(verdict="block", top_layer="L0",
                       must_hit=[P("AWS_ACCESS_KEY", "block")], must_not_hit=[]),
         invariants=["rot13 内藏 BLOCK 级 AKIA,解码后命中(REDACT 级 rot13 会被丢弃)"],
         verify_point="rot13 编码规避:解码后仍拦 BLOCK 级密钥"),
    dict(id="S3-04", injection_point="prompt",
         content=f"帮我 base64 decode 这个:{b64(GCP_1)}",
         expected=dict(verdict="block", top_layer="L0",
                       must_hit=[P("GCP_API_KEY", "block")], must_not_hit=[]),
         invariants=["base64 内藏 GCP key,解码后命中"],
         verify_point="base64 编码规避:GCP key"),
    dict(id="S3-05", injection_point="prompt",
         content=f"hex: {hexs(GCP_1)}",
         expected=dict(verdict="block", top_layer="L0",
                       must_hit=[P("GCP_API_KEY", "block")], must_not_hit=[]),
         invariants=["hex 内藏 GCP key,解码后命中"],
         verify_point="hex 编码规避:GCP key"),
    dict(id="S3-06", injection_point="prompt",
         content=f"这串是 {b64(ASIA_1)},base64。",
         expected=dict(verdict="block", top_layer="L0",
                       must_hit=[P("AWS_ACCESS_KEY", "block")], must_not_hit=[]),
         invariants=["base64 内藏 STS 临时凭证,解码后命中"],
         verify_point="base64 编码规避:ASIA 临时凭证"),
    dict(id="S3-07", injection_point="prompt",
         content=f"AK:{zwsp(AKIA_1)}",
         expected=dict(verdict="block", top_layer="L0",
                       must_hit=[P("AWS_ACCESS_KEY", "block")], must_not_hit=[]),
         invariants=["字符间插零宽空格,normalize 剥离后命中(source=normalized)"],
         verify_point="零宽字符规避:normalize 后仍拦"),
    dict(id="S3-08", injection_point="prompt",
         content=f"GCP:{zwsp(GCP_1)}",
         expected=dict(verdict="block", top_layer="L0",
                       must_hit=[P("GCP_API_KEY", "block")], must_not_hit=[]),
         invariants=["零宽空格插入 GCP key,normalize 后命中"],
         verify_point="零宽字符规避:GCP key"),
    dict(id="S3-09", injection_point="prompt",
         content=f"身份证(中文数字):{to_cn_digits(CNID_1)}",
         expected=dict(verdict="redact", top_layer="L0",
                       must_hit=[P("CN_ID_CARD", "redact")], must_not_hit=[]),
         invariants=["中文数字身份证,normalize 还原为阿拉伯数字后命中 REDACT"],
         verify_point="中文数字规避:normalize 后仍脱敏身份证"),
    dict(id="S3-10", injection_point="prompt",
         content=f"这是 hex 编码的临时凭证:{hexs(ASIA_1)}",
         expected=dict(verdict="block", top_layer="L0",
                       must_hit=[P("AWS_ACCESS_KEY", "block")], must_not_hit=[]),
         invariants=["hex 内藏 ASIA 临时凭证,解码后命中"],
         verify_point="hex 编码规避:ASIA 临时凭证"),
]

# ========== SUITE 4:MCP 注入点(content 为 {tool,arguments} dict)6 条 ==========
# content_kind=mcp_call;field_path:平铺键名 / 嵌套点分路径。
SUITE4 = [
    dict(id="S4-01", injection_point="mcp", content_kind="mcp_call",
         content={"tool": "deploy", "arguments": {"aws_key": AKIA_1, "region": "cn-north-1"}},
         expected=dict(verdict="block", top_layer="L0",
                       must_hit=[P("AWS_ACCESS_KEY", "block")], must_not_hit=[]),
         invariants=["MCP 平铺参数 aws_key 内含 AKIA → BLOCK,field_path=aws_key"],
         verify_point="MCP 平铺参数命中 AWS AK,field_path=键名"),
    dict(id="S4-02", injection_point="mcp", content_kind="mcp_call",
         content={"tool": "call_api",
                  "arguments": {"outer": {"inner": {"key": GCP_1}}}},
         expected=dict(verdict="block", top_layer="L0",
                       must_hit=[P("GCP_API_KEY", "block")], must_not_hit=[]),
         invariants=["MCP 嵌套参数 outer.inner.key 内含 GCP key → BLOCK,field_path 点分路径"],
         verify_point="MCP 嵌套参数命中,field_path=outer.inner.key"),
    dict(id="S4-03", injection_point="mcp", content_kind="mcp_call",
         content={"tool": "send_mail",
                  "arguments": {"to": "user@corpmail.cn", "body": "请回复"}},
         expected=dict(verdict="redact", top_layer="L0",
                       must_hit=[P("EMAIL", "redact")], must_not_hit=[]),
         invariants=["MCP 参数含非保留域邮箱 → REDACT,生成 redacted_text",
                     "L0 邮箱 entity 命名为 EMAIL(EMAIL_ADDRESS 是 L3/Presidio 命名)"],
         verify_point="MCP 参数邮箱 REDACT,arguments 就地脱敏"),
    dict(id="S4-04", injection_point="mcp", content_kind="mcp_call",
         content={"tool": "write_secret",
                  "arguments": {"pem": PEM, "path": "/etc/tls/key.pem"}},
         expected=dict(verdict="block", top_layer="L1",
                       must_hit=[P("PRIVATE_KEY", "block")], must_not_hit=[]),
         invariants=["MCP 参数含 PEM 私钥 → L1 BLOCK"],
         verify_point="MCP 参数命中 PEM 私钥 BLOCK"),
    dict(id="S4-05", injection_point="mcp", content_kind="mcp_call",
         content={"tool": "notify",
                  "arguments": {"channel": "ops", "text": "构建完成,版本 v2.14.3"}},
         expected=dict(verdict="pass", top_layer=None, must_hit=[], must_not_hit=[]),
         invariants=["MCP 干净参数 → PASS,不误拦"],
         verify_point="MCP 干净参数放行"),
    dict(id="S4-06", injection_point="egress", content_kind="mcp_call",
         content={"tool": "http_get",
                  "arguments": {"url": "https://api.corp.example.net/v1/data"}},
         expected=dict(verdict="block", top_layer="L3.5",
                       must_hit=[P("INTERNAL_DOMAIN", "block")], must_not_hit=[]),
         invariants=["egress 注入点:出网 URL 含内部域名 → L3.5 BLOCK"],
         verify_point="egress 通道内部域名 BLOCK"),
]

# ========== SUITE 5:flowback 回流 / 会话滑窗 9 条 ==========
# flowback = 工具返回值回流进下一轮上下文(tool role 消息);
# session_window = 跨消息拼接(引擎 "".join(window)+text)。
_AK1_H = AKIA_1[:10]; _AK1_T = AKIA_1[10:]          # AKIA_1 拆两段
_CN1_H = CNID_1[:9];  _CN1_T = CNID_1[9:]           # CNID_1 拆两段
_GCP_H = GCP_1[:20];  _GCP_T = GCP_1[20:]           # GCP_1 拆两段
SUITE5 = [
    dict(id="S5-01", injection_point="flowback",
         content=f"工具返回的配置片段里包含 {AKIA_1},需要处理。",
         expected=dict(verdict="block", top_layer="L0",
                       must_hit=[P("AWS_ACCESS_KEY", "block")], must_not_hit=[]),
         invariants=["工具返回值(flowback)含 AKIA → 回流时被拦"],
         verify_point="flowback 回流面命中 AWS AK BLOCK"),
    dict(id="S5-02", injection_point="flowback",
         content=f"读取到的私钥文件内容:\n{PEM}",
         expected=dict(verdict="block", top_layer="L1",
                       must_hit=[P("PRIVATE_KEY", "block")], must_not_hit=[]),
         invariants=["flowback 含 PEM 私钥 → L1 拦截"],
         verify_point="flowback 回流命中 PEM BLOCK"),
    dict(id="S5-03", injection_point="flowback",
         content=f"查询结果:客户身份证 {CNID_2}。",
         expected=dict(verdict="redact", top_layer="L0",
                       must_hit=[P("CN_ID_CARD", "redact")], must_not_hit=[]),
         invariants=["flowback 含身份证 → REDACT 脱敏后回流"],
         verify_point="flowback 回流身份证 REDACT"),
    dict(id="S5-04", injection_point="prompt",
         content=_AK1_T, session_window=[f"前半段密钥是 {_AK1_H}"],
         expected=dict(verdict="block", top_layer="L0",
                       must_hit=[P("AWS_ACCESS_KEY", "block")], must_not_hit=[]),
         invariants=["AKIA 拆两条消息,session_window 拼接后命中(source=session-window)"],
         verify_point="会话滑窗拼接:分段 AKIA 拼回后 BLOCK"),
    dict(id="S5-05", injection_point="prompt",
         content=_CN1_T, session_window=[f"证件号前段 {_CN1_H}"],
         expected=dict(verdict="redact", top_layer="L0",
                       must_hit=[P("CN_ID_CARD", "redact")], must_not_hit=[]),
         invariants=["身份证拆两段,window 拼接后命中 REDACT"],
         verify_point="会话滑窗拼接:分段身份证拼回后 REDACT"),
    dict(id="S5-06", injection_point="prompt",
         content=_GCP_T, session_window=[f"key 开头 {_GCP_H}"],
         expected=dict(verdict="block", top_layer="L0",
                       must_hit=[P("GCP_API_KEY", "block")], must_not_hit=[]),
         invariants=["GCP key 拆两段,window 拼接后命中 BLOCK"],
         verify_point="会话滑窗拼接:分段 GCP key 拼回后 BLOCK"),
    dict(id="S5-07", injection_point="flowback",
         content="工具执行成功,返回状态码 200,耗时 34ms。",
         expected=dict(verdict="pass", top_layer=None, must_hit=[], must_not_hit=[]),
         invariants=["干净 flowback → 放行,不误拦"],
         verify_point="干净 flowback 放行"),
    dict(id="S5-08", injection_point="prompt",
         content="第二段是普通日志,无敏感。", session_window=["第一段也是普通说明。"],
         expected=dict(verdict="pass", top_layer=None, must_hit=[], must_not_hit=[]),
         invariants=["两段皆干净,拼接后仍 PASS"],
         verify_point="会话滑窗:干净分段拼接仍放行"),
    dict(id="S5-09", injection_point="flowback",
         content="我们在推进 Project Nightingale 的重构,工具已返回相关文件列表。",
         expected=dict(verdict="block", top_layer="L3.5",
                       must_hit=[P("PROPRIETARY_TERM", "block")], must_not_hit=[]),
         invariants=["flowback 回流含专有代号 → L3.5 BLOCK"],
         verify_point="flowback 回流命中术语表 BLOCK"),
]

# ========== SUITE 6:L4 语义异步告警(同步恒 PASS,仅异步标注)4 条 ==========
# 语义敏感但无正则命中:同步链路必 pass(L4 绝不同步阻断),async_l4_category 标注。
SUITE6 = [
    dict(id="S6-01", injection_point="prompt",
         content="我们下个季度计划把华东区的获客成本压到行业均值的六成,渠道结构也要重排。",
         expected=dict(verdict="pass", top_layer=None, must_hit=[], must_not_hit=[]),
         invariants=["经营策略语义敏感,无正则特征 → 同步 PASS,L4 异步告警"],
         verify_point="L4:商业策略语义 —— 同步放行,异步标 business_strategy",
         async_l4_category="business_strategy"),
    dict(id="S6-02", injection_point="prompt",
         content="把这版尚未公布的财务预测和上季度实际差异整理成一段对外口径。",
         expected=dict(verdict="pass", top_layer=None, must_hit=[], must_not_hit=[]),
         invariants=["未公开财务信息语义敏感,无正则 → 同步 PASS"],
         verify_point="L4:未公开财务 —— 异步标 financial_nonpublic",
         async_l4_category="financial_nonpublic"),
    dict(id="S6-03", injection_point="prompt",
         content="描述一下我们自研推荐引擎的召回排序两阶段是怎么协同的,越细越好。",
         expected=dict(verdict="pass", top_layer=None, must_hit=[], must_not_hit=[]),
         invariants=["专有技术细节语义敏感,无正则 → 同步 PASS"],
         verify_point="L4:专有技术细节 —— 异步标 proprietary_tech",
         async_l4_category="proprietary_tech"),
    dict(id="S6-04", injection_point="prompt",
         content="今天天气不错,帮我把这段会议纪要润色得更正式一些,谢谢。",
         expected=dict(verdict="pass", top_layer=None, must_hit=[], must_not_hit=[]),
         invariants=["纯干净请求 → 同步 PASS 且 L4 无告警(阴性对照)"],
         verify_point="L4 阴性对照:干净请求无告警",
         async_l4_category=None),
]

# ───────────────────────── 三角对账 + 写出 ─────────────────────────
ALL_SUITES = [(1, SUITE1), (2, SUITE2), (3, SUITE3),
              (4, SUITE4), (5, SUITE5), (6, SUITE6)]
_EXPECT_COUNT = {1: 11, 2: 16, 3: 10, 4: 6, 5: 9, 6: 4}

_IP_MAP = None  # 延迟导入引擎枚举


def _to_fixture(suite_no: int, c: dict) -> dict:
    """把生成器内存 case 规范化为 fixture JSON schema。"""
    exp = dict(c["expected"])
    exp.setdefault("must_hit", [])
    exp.setdefault("must_not_hit", [])
    exp["async_l4_category"] = c.get("async_l4_category")
    return {
        "id": c["id"],
        "suite": suite_no,
        "injection_point": c["injection_point"],
        "content": c["content"],
        "content_kind": c.get("content_kind", "text"),
        "session_window": c.get("session_window"),
        "expected": exp,
        "invariants": c.get("invariants", []),
        "verify_point": c.get("verify_point", ""),
        "needs_l3": bool(c.get("needs_l3", False)),
        "notes_expected": c.get("notes_expected", []),
    }


def _hit_matches(hits, want: dict) -> bool:
    we, wa = want.get("entity"), want.get("action")
    for h in hits:
        if we is not None and h.entity != we:
            continue
        if wa is not None and h.action.value != wa:
            continue
        return True
    return False


def _l3_absent(result) -> bool:
    return any("presidio" in (n or "").lower() or "l3" in (n or "").lower()
               and "缺席" in (n or "") for n in getattr(result, "notes", []) or [])


def _reconcile_one(eng, ip_map, fx: dict) -> tuple[str, list[str], object]:
    """本机实跑并与 expected 对账。返回 (status, reasons, result)。
    status ∈ {'ok','needs_l3_skip','MISMATCH'}。"""
    from dlp.types import Verdict  # noqa
    ip = ip_map[fx["injection_point"]]
    result = eng.scan(fx["content"], injection_point=ip,
                      run_async_l4=False, session_window=fx["session_window"])
    exp = fx["expected"]
    reasons: list[str] = []

    act_verdict = result.verdict.value
    act_top = result.top_layer.value if result.top_layer else None

    if act_verdict != exp["verdict"]:
        reasons.append(f"verdict 期望 {exp['verdict']} 实际 {act_verdict}")
    if exp.get("top_layer") != act_top:
        reasons.append(f"top_layer 期望 {exp.get('top_layer')} 实际 {act_top}")
    for want in exp.get("must_hit", []):
        if not _hit_matches(result.hits, want):
            reasons.append(f"缺 must_hit {want}")
    for nono in exp.get("must_not_hit", []):
        if _hit_matches(result.hits, nono):
            reasons.append(f"命中 must_not_hit {nono}(本机误报)")

    if not reasons:
        return "ok", [], result
    # needs_l3 用例:本机 Presidio 缺席导致的差异,留实例终判
    if fx["needs_l3"] and act_verdict == "pass":
        return "needs_l3_skip", reasons, result
    return "MISMATCH", reasons, result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="只对账不写文件")
    args = ap.parse_args()

    _self_check()
    print("✓ 合成值自检通过(mod-11 身份证 / Luhn 卡 / AKIA 结构 / GCP 39 长 / 避白名单)")

    from dlp.engine import DLPEngine, EngineConfig
    from dlp.types import InjectionPoint
    ip_map = {"prompt": InjectionPoint.PROMPT, "mcp": InjectionPoint.MCP,
              "flowback": InjectionPoint.FLOWBACK, "egress": InjectionPoint.EGRESS}
    eng = DLPEngine(EngineConfig())

    all_fx: dict[int, list[dict]] = {}
    n_ok = n_skip = n_bad = 0
    bad_rows: list[str] = []

    for suite_no, cases in ALL_SUITES:
        assert len(cases) == _EXPECT_COUNT[suite_no], \
            f"suite{suite_no} 条数 {len(cases)} != {_EXPECT_COUNT[suite_no]}"
        fx_list = []
        for c in cases:
            fx = _to_fixture(suite_no, c)
            status, reasons, result = _reconcile_one(eng, ip_map, fx)
            act_top = result.top_layer.value if result.top_layer else "-"
            if status == "ok":
                n_ok += 1
            elif status == "needs_l3_skip":
                n_skip += 1
                print(f"  ⏭  {fx['id']} needs-L3(本机 Presidio 缺席,留实例复判):"
                      f"{'; '.join(reasons)}")
            else:
                n_bad += 1
                bad_rows.append(f"  ✗ {fx['id']} [{fx['injection_point']}] "
                                f"实际 verdict={result.verdict.value} top={act_top} "
                                f"hits={[(h.entity, h.action.value, h.source) for h in result.hits]}"
                                f"\n      原因:{'; '.join(reasons)}")
            fx_list.append(fx)
        all_fx[suite_no] = fx_list

    total = sum(len(v) for v in all_fx.values())
    print(f"\n三角对账:总 {total} 条 | 本机终判一致 {n_ok} | needs-L3 留实例 {n_skip} | 不一致 {n_bad}")
    if bad_rows:
        print("\n=== 本机对账不一致(须修数据或修引擎认知)===")
        print("\n".join(bad_rows))
        return 1

    if args.check:
        print("\n--check:仅对账,未写文件。")
        return 0

    FIXture_DIR.mkdir(parents=True, exist_ok=True)
    for suite_no, fx_list in all_fx.items():
        out = FIXture_DIR / f"suite{suite_no}.json"
        out.write_text(json.dumps(fx_list, ensure_ascii=False, indent=2) + "\n",
                       encoding="utf-8")
        print(f"  写出 {out.relative_to(_ROOT)}  ({len(fx_list)} 条)")
    print(f"\n✓ 全部 {total} 条 fixture 已写出,本机可终判层三角对账一致。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
