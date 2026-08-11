"""L4 语义 LLM(SPEC §5-L4)—— 秒级,**仅异步告警**。

后端:Bedrock(us-west-2)Qwen3-32B(主)+ Llama-3.1-8B(对照)。
**功能验证标定,非生产**(报告必写:生产 L4 须自托管/VPC-only)。
绝不写入 verdict。run_async_l4=True 时同步等待仅为单测断言方便。

超时:analyze/`_bedrock_alert` 接受可选 `timeout_s`——None(默认)保持历来硬编码
(connect 2s/read 5s),不改方案一/单测行为;调用方(如方案二 :9000 sync 模式)传入
显式墙钟预算时,据此派生 boto connect/read_timeout,让 Bedrock 调用不显著超出该预算。

识别:专有源码(定价引擎伪装注释)、自研业务逻辑(风控权重/排序权重/定价算法)。
控告警疲劳:通用/开源风格代码(快排/debounce)→ 不产 proprietary 告警。
"""
from __future__ import annotations

import json
import re

from .types import AsyncAlert, Layer

# 标定用模型 id(报告注明:非生产配置)。
# 2026-07-29 在 <TEST_INSTANCE_ID> 实测:qwen.qwen3-32b-v1:0 直连可用;
# us.qwen.qwen3-32b-* 报 ValidationException(无该 inference profile)。
CALIBRATION_MODELS = {
    "main": "qwen.qwen3-32b-v1:0",
    "control": "meta.llama3-1-8b-instruct-v1:0",
}

# —— 离线启发式回退(Bedrock 不可达/未开启时,harness 仍能验"该不该告警"的方向)——
# 专有信号:业务领域词 + 权重/公式/阈值等"自研逻辑"特征
_PROPRIETARY_BIZ = re.compile(
    r"(风控|风险评分|risk[_ ]?score|定价|pricing|margin|利润率|授信|信用额度|"
    r"排序权重|ranking[_ ]?weight|反欺诈|fraud|额度|费率)",
    re.IGNORECASE,
)
# 逻辑形状:权重/系数/阈值/公式,或"× 0.d / * 0.d"这类加权系数写法。
# ★ 修真机 bug:用户写 "risk_score = 0.3 × 逾期指标 + 0.7 × 额度指标",原正则
#   只认半角 `*` 和 `score[+\-*]`(紧邻),既不认全角乘号 ×(U+00D7)也不认 `score =`,
#   导致 heuristic logic=False、biz&logic 不成立而漏告警。此处补:
#   - 全角/半角乘号后接 0.d 系数:[*×] \s* 0\.\d
#   - score 后带 =/:/+/-/×/* 任一(容许空格):公式定义写法
_LOGIC_SHAPE = re.compile(
    r"(weight|系数|阈值|threshold|[*×]\s*0\.\d|formula|公式|score\s*[+\-*×=:])",
    re.IGNORECASE,
)
# 专有源码伪装:注释说"通用工具"但函数名/常量像内部系统
_DISGUISE = re.compile(r"(内部|internal|proprietary|专有|机密|confidential)", re.IGNORECASE)
# 通用/开源风格(控告警疲劳):经典算法,无业务领域词
_GENERIC_ALGO = re.compile(
    r"(quicksort|快速排序|bubble\s*sort|debounce|throttle|binary\s*search|"
    r"二分查找|冒泡|memoize|fibonacci)",
    re.IGNORECASE,
)


def _heuristic_alert(text: str) -> AsyncAlert | None:
    generic = bool(_GENERIC_ALGO.search(text))
    biz = bool(_PROPRIETARY_BIZ.search(text))
    logic = bool(_LOGIC_SHAPE.search(text))
    disguise = bool(_DISGUISE.search(text))

    if generic and not biz:
        return None  # 通用算法 → 不告警(CTRL-19/L4-16)

    if biz and logic:
        return AsyncAlert(Layer.L4, "proprietary-business-logic", 0.7,
                          "业务领域词 + 自研逻辑特征(权重/公式/阈值)",
                          text[:200], "heuristic:offline")
    if disguise:
        return AsyncAlert(Layer.L4, "proprietary-source", 0.6,
                          "注释/命名含内部专有标记", text[:200], "heuristic:offline")
    return None


def _bedrock_alert(
    text: str, model_key: str, timeout_s: float | None = None
) -> AsyncAlert | None:
    """调 Bedrock Converse 做 1-token 判定。失败则返回 None(交回退)。

    timeout_s: 显式墙钟预算(秒)。None -> 保持硬编码 connect=2/read=5(历来行为,
    方案一同步腿/离线单测不受影响);非 None -> read_timeout=timeout_s、
    connect_timeout=min(2.0, timeout_s),让 boto 不显著超出调用方给定的预算。
    """
    try:
        import boto3  # 延迟导入:离线环境无 boto3 也不阻塞
    except ImportError:
        return None
    model_id = CALIBRATION_MODELS.get(model_key, CALIBRATION_MODELS["main"])
    prompt = (
        "You are a corporate data-leak classifier. The content below is about to be "
        "sent to an EXTERNAL cloud LLM. Decide if it exposes company-internal "
        "sensitive information in one of these categories:\n"
        "- proprietary-source: proprietary source code (incl. disguised as comments/docs)\n"
        "- proprietary-business-logic: self-developed pricing/risk/ranking weights, "
        "formulas, thresholds\n"
        "- proprietary_tech: internal architecture/algorithm details of self-built systems\n"
        "- business_strategy: non-public plans (market/channel/cost/expansion strategy)\n"
        "- financial_nonpublic: unpublished financials (forecasts, unreleased results)\n"
        "Generic/open-source algorithms, public knowledge, and mundane daily requests "
        "are NOT sensitive. Answer strictly as JSON: {\"sensitive\":true|false,"
        "\"category\":\"proprietary-source|proprietary-business-logic|proprietary_tech|"
        "business_strategy|financial_nonpublic|none\","
        "\"confidence\":0-1,\"reason\":\"...\"}\n\nCONTENT:\n" + text[:4000]
    )
    try:
        # ★ 同步阻断路径:Bedrock 调用被计入 addon DLP_TIMEOUT(默认 8s)总预算。
        #   L0–L3 已占一部分,故给 Bedrock 配硬超时 + 有限重试,宁可 L4 失败回退启发式,
        #   也不拖爆 addon 8s 线(拖爆 → fail-closed 503 → Kiro 反复重试)。
        from botocore.config import Config as _BotoConfig

        # timeout_s=None -> 历来硬编码 2/5;非 None -> 依调用方墙钟预算派生,
        # read 用满预算、connect 收敛到 min(2, 预算),retries 恒 1 次(宁可回退启发式)。
        if timeout_s is None:
            _connect_to, _read_to = 2, 5
        else:
            _read_to = max(0.1, timeout_s)
            _connect_to = min(2.0, _read_to)
        client = boto3.client(
            "bedrock-runtime",
            region_name="us-west-2",
            config=_BotoConfig(
                connect_timeout=_connect_to,
                read_timeout=_read_to,
                retries={"max_attempts": 1, "mode": "standard"},
            ),
        )
        resp = client.converse(
            modelId=model_id,
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig={"maxTokens": 200, "temperature": 0.0},
        )
        out = resp["output"]["message"]["content"][0]["text"]
        data = json.loads(re.search(r"\{.*\}", out, re.DOTALL).group(0))
    except Exception:
        return None
    if not data.get("sensitive"):
        return None
    return AsyncAlert(Layer.L4, data.get("category", "proprietary-source"),
                      float(data.get("confidence", 0.5)), data.get("reason", ""),
                      text[:200], f"bedrock:{model_key}:{model_id}")


def analyze(
    text: str,
    use_bedrock: bool = False,
    model_key: str = "main",
    timeout_s: float | None = None,
) -> list[AsyncAlert]:
    """产出 0..1 条 AsyncAlert。use_bedrock=False 时走离线启发式(标定/单测)。

    timeout_s 仅在 use_bedrock=True 时透传给 `_bedrock_alert` 作墙钟预算;
    None(默认)保持历来行为,现有调用点(engine.py/gateway/run_layers/
    inspect_cases/l4_calibration)零改动。
    """
    alert = None
    if use_bedrock:
        alert = _bedrock_alert(text, model_key, timeout_s)
    if alert is None:
        alert = _heuristic_alert(text)
    return [alert] if alert else []
