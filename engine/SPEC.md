# DLP 分层引擎 — 接口契约(SPEC)

> **唯一真源(single source of truth)**。实现模块、fixtures、离线 harness、对抗审计都以本文件为准。
> 对应设计稿:`../方案一-litellm-gateway/方案一-03-测试方案.md`(§2 层实现表、§4 场景矩阵、§5 指标)。
> 本文件只定义**接口/数据结构/语义/不变量**,不含实测数字。

---

## 0. 范围与铁律(实现时不可违背)

1. **同步链路只放 L0–L3.5**(确定性、亚秒)。`scan()` 返回的 `verdict` 只由 L0–L3.5 决定。
2. **引擎 `scan()` 里 L4 永不进入同步 verdict**。L4 仅产出**异步告警对象**(`AsyncAlert`),`scan()` 同步返回时 L4 尚未跑完;凡设计稿中 `dlp_layer=L4` 的场景,其**同步 `expected_verdict` 必为 `pass`**,只验异步告警。
   > ⚠ **部署层例外(不破本铁律)**:方案二 `:9000` 判定服务提供**显式可选**的 `DLP_L4_MODE=sync` 阻断态——此时高置信 L4 告警会在 **server 层(引擎之外)** 就地合成 `BLOCK`(`top_layer=L4`)。引擎自身仍恒 `run_async_l4=False`/`l4_sync_block=False`,`scan()` 永不因 L4 改 verdict;`sync` 只是调用方在引擎之上叠的部署策略,且超时即降级为异步告警放行(见 §L4)。committed 演示默认是 `async`(不改 verdict),非 `sync`。
3. **best-effort 检测,非硬预防**。通道级外带(套件4)、专有源码(套件6)结构上检不到——这些场景的"期望"是**通道管控/异步告警口径**,不是内容引擎能给的 block。
4. **不伪造实测**。harness 输出的是"实际 verdict vs oracle"的比对矩阵,不手写数字。
5. **redact 后结构必须仍合法**:JSON 入参 redact 后仍是合法 JSON(MCP-06);测试断言字面量(保留域名/示例值)不被改写(FP-06)。

---

## 1. 顶层数据结构(`dlp/types.py`)

```python
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

class Verdict(str, Enum):
    PASS   = "pass"      # 放行
    REDACT = "redact"    # 脱敏后放行
    BLOCK  = "block"     # 拦截

class Layer(str, Enum):
    L0   = "L0"          # 正则/词表
    L1   = "L1"          # detect-secrets/gitleaks 类签名
    L2   = "L2"          # 高熵 + 语境
    L3   = "L3"          # Presidio PII/NER
    L35  = "L3.5"        # 术语表/EDM (Aho-Corasick)
    L4   = "L4"          # 语义 LLM —— 仅异步

class InjectionPoint(str, Enum):
    PROMPT   = "prompt"        # 用户消息 / 代码上下文
    MCP      = "mcp"           # MCP 工具调用参数
    FLOWBACK = "flowback"      # 工具返回值回流进下一轮上下文
    EGRESS   = "egress"        # 通道级(shell/git/http-body/db)——由通道管控判定

@dataclass
class Hit:
    layer: Layer               # 命中层
    rule: str                  # 规则标识,如 "aws_access_key" / "cn_id_card" / "glossary:Project Nightingale"
    entity: str                # 实体类型,如 "AWS_ACCESS_KEY" / "PERSON" / "CREDIT_CARD" / "PROPRIETARY_TERM"
    span: tuple[int, int]      # 在【归一化后文本】中的 [start,end);无精确 span 用 (-1,-1)
    matched: str               # 命中的原文片段(用于 redact 定位与报告;报告展示时自行截断)
    action: Verdict            # 该 hit 期望的动作:BLOCK 或 REDACT(单个 hit 不会是 PASS)
    confidence: float = 1.0    # [0,1];L3 用 Presidio score,确定性层固定 1.0
    source: str = "normalized" # "raw"(原文命中) / "normalized"(归一化后) / "decoded:base64" 等,标注命中来自哪条预处理路径
    field_path: str | None = None  # MCP/嵌套 JSON 命中的字段路径,如 "headers.Authorization" / "meta.debug.env[1].v"

@dataclass
class AsyncAlert:
    layer: Layer               # 恒为 Layer.L4
    category: str              # "proprietary-source" / "proprietary-business-logic"
    confidence: float
    rationale: str             # LLM 给的简短理由(供追溯)
    context: str               # 触发告警的上下文片段(截断)
    model: str                 # "bedrock:qwen3-32b" / "bedrock:llama-3.1-8b" —— 标定用,非生产

@dataclass
class ScanResult:
    verdict: Verdict                         # 同步裁决:仅由 L0–L3.5 hits 聚合
    hits: list[Hit] = field(default_factory=list)          # 所有同步命中(可跨层多条)
    top_layer: Layer | None = None           # 触发最终 verdict 的"最低有效层"(设计稿"层"列的判据)
    redacted_text: str | None = None         # verdict==REDACT 时给出脱敏后文本;BLOCK/PASS 为 None
    async_alerts: list[AsyncAlert] = field(default_factory=list)  # L4 告警(同步返回时通常为空,见 §4)
    latency_ms: dict[str, float] = field(default_factory=dict)    # 每层耗时:{"L0":0.3,"L1":..,"total":..}
    normalized_variants: list[str] = field(default_factory=list)  # 预处理产出的所有回扫变体(调试/审计用)
    notes: list[str] = field(default_factory=list)          # 已知逃逸缺口标注,如 "未解码:未白名单外发目标 → egress 兜底"
```

---

## 2. verdict 聚合规则(`scan()` 如何从多条 hit 得出单一裁决)

命中可能跨多层、多条。最终 `verdict` 与 `top_layer` 按下述**确定性规则**聚合:

1. 若任一 `hit.action == BLOCK` → `verdict = BLOCK`。
2. 否则若存在 `hit.action == REDACT` → `verdict = REDACT`,并产出 `redacted_text`。
3. 否则 → `verdict = PASS`。
4. `top_layer` = 触发最终 verdict 的那些 hit 里**层序最低**者(L0<L1<L2<L3<L3.5)。设计稿"层"列即此值。
   - 例:L0-02 身份证+手机都 REDACT → verdict=REDACT, top_layer=L0。
   - 例:MCP-01 AKIA 同时命中 L0(正则)与 L1(签名),都 BLOCK → verdict=BLOCK, top_layer=L0。
5. **BLOCK 优先于 REDACT**:一条 BLOCK + 多条 REDACT → 整体 BLOCK(硬秘密在场不脱敏放行)。

> action 归属(每条规则产出 BLOCK 还是 REDACT)见 §5 各层规格。总原则:**不可逆秘密/凭证=BLOCK;可脱敏保留业务可用性的 PII=REDACT**。

---

## 3. 引擎入口(`dlp/engine.py`)

```python
class DLPEngine:
    def __init__(self, config: EngineConfig | None = None): ...

    def scan(
        self,
        content: str | dict,          # str=prompt/flowback 文本;dict=MCP 工具调用 {"tool","arguments":{...}}
        *,
        injection_point: InjectionPoint = InjectionPoint.PROMPT,
        run_async_l4: bool = False,   # 离线单测默认 False(只验同步);套件6 标定时置 True 同步等待 L4 便于断言
        session_window: list[str] | None = None,  # 跨消息滑窗:本请求之前的同会话文本片段(EVA-03/04/18 拼接依赖)
    ) -> ScanResult: ...
```

**处理流水(顺序固定)**:

```
1. 抽取待扫文本单元(extract):
   - PROMPT/FLOWBACK: 整个 content 作为一个文本单元
   - MCP: 递归展开 arguments 的所有【字符串叶子】,每个叶子带 field_path(见 §6);
          tool 名、path 类字段也扫但命中归属到对应 field_path
   - session_window 里的历史片段与当前文本【拼接】后另作一个"跨消息单元"参与 L0/L1(EVA-03/04/18)
2. 归一化预处理(normalize,§4)→ 每个文本单元产出 [原文, 归一化文本, 解码变体...] 一组"回扫变体"
3. 对每个变体依次跑 L0 → L1 → L2 → L3 → L3.5,收集 hits(记录 hit.source 指明来自哪个变体)
4. 去重:同 (rule, span, field_path) 的 hit 合并,保留最高 confidence
5. 聚合 verdict/top_layer(§2);若 verdict==REDACT 生成 redacted_text
6. 若 run_async_l4: 跑 L4 → async_alerts(不影响 verdict);否则 async_alerts 留空、notes 标注"L4 未在同步跑"
7. 填 latency_ms,返回 ScanResult
```

---

## 4. 归一化预处理(`dlp/normalize.py`)—— 套件3 的命根子

```python
def normalize(text: str) -> str: ...
def decode_variants(text: str) -> list[str]: ...   # 返回可逆编码的解码结果(可能空)
def expand(text: str) -> list[str]: ...            # = [text, normalize(text), *decode_variants(normalize(text))] 去重
```

- `normalize(text)`:
  1. Unicode **NFKC** 规范化(全角→半角、兼容字符折叠)。
  2. 去**零宽字符**:U+200B/200C/200D/FEFF/2060。
  3. 去常见**分隔符混淆**:命中候选内的 `-`/空格/`.`/`_`(仅在"疑似连续 token"场景;不破坏正常文本语义——实现用"先原文扫,再去分隔符扫"双跑,而非全局删)。
  4. 中文数字→阿拉伯数字(身份证/手机场景,EVA-11)。
- `decode_variants(text)`:对文本中的可疑片段尝试
  - **base64**(`[A-Za-z0-9+/]{16,}={0,2}`,解码后是可打印 ASCII 才保留),
  - **hex**(`(?:[0-9a-fA-F]{2}){8,}`),
  - **rot13**(整体或片段),
  - **char-code / `\xNN` / `chr()` 拼接**(EVA-02)。
  解出的明文各作一条变体回扫。**解不出或解出乱码 → 丢弃该变体**(不产生噪声)。
- **拼接折叠**(EVA-04/18):相邻字符串字面量(`"A"+"B"`、`"A" "B"`、`part1+part2` 变量拼接的**同段**)常量折叠为一个候选串再扫。跨消息拼接靠 `session_window`(EVA-03)。

> 铁律:**先扫原文,再扫每个变体**。变体命中时 `hit.source` 必须标明(如 `"decoded:base64"`),否则报告无法区分"明文泄漏"与"编码规避"。

---

## 5. 各层规格

### L0 正则/词表(`dlp/l0_regex.py`)—— 亚毫秒,同步

| rule | 模式 | entity | action | 备注 |
|---|---|---|---|---|
| `aws_access_key` | `AKIA[0-9A-Z]{16}` | AWS_ACCESS_KEY | BLOCK | **官方示例白名单**:`AKIAIOSFODNN7EXAMPLE` 在白名单→PASS(FP-05);但 L0-01 里 AKIA+**真 secret 同现**仍 BLOCK(白名单只豁免示例 key 单独出现) |
| `aws_secret_key` | 40 字符 base64ish + 语境 `secret`/`aws_secret_access_key` | AWS_SECRET_KEY | BLOCK | 需语境词,纯 40 字符串不判(防 FP) |
| `gcp_api_key` | `AIza[0-9A-Za-z_\-]{35}` | GCP_API_KEY | BLOCK | L0-20 回流路径同样过 |
| `cn_id_card` | 18 位,**mod-11 校验位**(末位可 X) | CN_ID_CARD | **REDACT** | L0-02;**校验位不过→不命中**(L0-03 订单号) |
| `cn_phone` | `(?<!\d)1[3-9]\d{9}(?!\d)` | CN_PHONE | **REDACT** | **需联系人语境**或与身份证/姓名同现才判;孤立 `tracking_no=138...` 不判(L0-03) |
| `email` | RFC-ish | EMAIL | **REDACT** | **RFC2606 保留域名**(example.com/.org/.net、test./invalid.)白名单→PASS(FP-06) |
| `regex_pattern_defn` | 判"这是正则定义不是真值":含 `[0-9A-Z]{16}`/字符类/量词 | — | 降权 | FP-10:secret-scanner 规则文件里的 `AKIA[0-9A-Z]{16}` 是模式不是值→不 BLOCK |

- **官方/测试白名单**(集中在 `l0_regex.py` 的 `WHITELIST`):`AKIAIOSFODNN7EXAMPLE`、RFC2606 域名。
- action 归属:凭证=BLOCK;身份证/手机/邮箱=REDACT。

### L1 签名(`dlp/l1_secrets.py`)—— ~10ms,同步

| rule | 命中 | entity | action |
|---|---|---|---|
| `pem_private_key` | `-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----` | PRIVATE_KEY | BLOCK(L1-04) |
| `pem_certificate` | `-----BEGIN CERTIFICATE-----` | CERTIFICATE | **PASS**(FP-11:公钥证书可发,**按 PEM 头精确区分**私钥 vs 证书) |
| `stripe_live` | `sk_live_[0-9a-zA-Z]{16,}` | STRIPE_KEY | BLOCK(L1-05) |
| `github_pat` | `ghp_[0-9A-Za-z]{36}` | GITHUB_PAT | BLOCK |
| `openai_key` | `sk-proj-[...]` / `sk-[A-Za-z0-9]{20,}` | OPENAI_KEY | BLOCK(MCP-05) |
| `jwt` | `eyJ...\.eyJ...\.[...]` | JWT | BLOCK,**但公开 demo(jwt.io John Doe payload)白名单→PASS**(FP-12) |
| `high_entropy_prefixed` | 已知前缀 + 高熵尾 | GENERIC_SECRET | BLOCK |

- **占位符白名单**:`CHANGE_ME`/`your-*-here`/`xxx`/`<...>` → PASS(L1-06 .env.example)。
- **lockfile 豁免**:`sha512-`/`integrity` 字段、40 位 git SHA → 交 L2 语境判定,L1 不签名命中(FP-02/FP-04)。

### L2 高熵 + 语境(`dlp/l2_entropy.py`)—— ~10ms,同步

- Shannon 熵阈值(base64 charset ~4.0+ bits/char)**且**必须有**赋值/密钥语境词**(`password`/`passwd`/`pwd`/`secret`/`token`/`api_key`/`apikey`/`=`/`:` 右侧)才 → BLOCK。
- **无语境的高熵串一律 PASS**:UUID v4(8-4-4-4-12 结构豁免,FP-01)、`data:image/*;base64,`(前缀豁免,FP-03)、git SHA、build_id、base64 资源指纹、lockfile `sha512-` integrity(FP-04/L2-08/MCP-10/L3-11 也靠此)。
- L2-07:`{"password":"Xq9$Lm2!Vt7#..."}` = 键语境 + 值高熵 → BLOCK(action=BLOCK)。
- action:L2 命中恒 BLOCK(有语境的高熵秘密不脱敏)。

### L3 Presidio(`dlp/l3_presidio.py`)—— ≤100ms/100token,同步

- 调**官方 analyzer 容器**(HTTP `http://presidio-analyzer:5002/analyze`)+ `BatchAnalyzerEngine`;**加载中文识别器**(zh 语言 + 拼音中文名 NER,MCP-06)。
- 实体→action:`PERSON`/`EMAIL_ADDRESS`/`PHONE_NUMBER`/`LOCATION`/`CREDIT_CARD` → **REDACT**(L3-09/L3-10)。
- **CREDIT_CARD**:Luhn 通过才命中;**测试卡号白名单**(`4111...`/`5555...4444`/`378282...`)→ PASS(FP-08);**"流水号/批次号"语境**把 CREDIT_CARD 置信度降到阈值下→PASS(L3-11)。
- **公开人名/普通地名语境降权**:开源作者真名(Salvatore/Guido)、泛指"上海团队" → 不同步 redact(FP-07)。
- **保留测试域名**:redact 不改写 `alice@example.com` 等断言字面量(FP-06 与 L0 白名单一致)。
- Presidio 不可达时:**fail-closed 或告警,不得静默 pass**(§7 降级安全)。离线单测里 Presidio 容器不在则该层 `notes` 标注 "L3 skipped(analyzer 不可达)" 并按缺 L3 处理,但**不得把本应 L3 命中的 fixture 记为 PASS**——harness 需能区分"真 PASS"与"L3 缺席"。

### L3.5 术语表/EDM(`dlp/l35_glossary.py`)—— 亚毫秒,同步

- **Aho-Corasick** 多模式匹配内部术语表(`GLOSSARY` 列表)。
- **约束(避免撞普通英文,FP-09/L35-13)**:
  1. **完整专有短语**匹配(`Project Nightingale` 整体,裸 `nightingale` 不命中);
  2. **词边界**(`\b`);
  3. **大小写敏感或专有大小写模式**(社区版小写 `nightingale` != 代号 `Nightingale`)。
- 命中→ action 视术语类别:代号/项目名默认 BLOCK(L35-12);出现在 commit/工单里可 REDACT(MCP-04)。术语表每条带 `action` 字段。
- 术语表初始条目(从设计稿):`Project Nightingale`、`KunlunPay`、`region-cn-shadow`、`PROJECT-TITAN`、`Falcon`(仅专有语境)、`internal-margin-formula`、`SEV2-48213`/`SEV\d-\d+`(工单号模式)。**`*.corp.example.net` 内部域名**也在此层或 L0。

### L4 语义 LLM(`dlp/l4_semantic.py`)—— 秒级,**引擎侧仅异步告警**

- 后端:Bedrock(us-west-2)**Qwen3-32B(主)+ Llama-3.1-8B(对照)**,**功能验证标定,非生产**(报告必写)。
- 输入待扫文本,输出 1-token 判定(敏感/不敏感)+ 置信度 + 简短理由 → `AsyncAlert(category, confidence, rationale, ...)`。
- **引擎绝不写入 verdict**。`run_async_l4=True` 时同步等待仅为**单测断言**方便,生产是队列异步。
- `analyze(text, use_bedrock=False, model_key="main", timeout_s=None)`:`timeout_s` 仅在 `use_bedrock=True` 时透传给 boto(`read_timeout=timeout_s`、`connect_timeout=min(2,timeout_s)`);`None`(默认)保持历来硬编码 2/5,现有调用点零改动。
- 识别:专有源码(EVA-05 定价引擎伪装注释)、自研业务逻辑(L4-14 风控权重、MCP-11 排序权重、L4-15 定价算法)。
- **控告警疲劳**:通用/开源风格代码(CTRL-19 快排、L4-16 debounce)→ 不产 proprietary 告警。

**部署层三态编排(方案二 `:9000`,引擎之外)**:判定服务用 `DLP_L4_MODE ∈ {off, async, sync}` 在 `scan()` 之后自持后台线程池直调 `analyze`——

| mode | 请求线程 | verdict 可被 L4 改 | 落 sink | committed 默认 |
|---|---|---|---|---|
| `off` | 不跑 L4 | 否 | 否 | — |
| **`async`** | 立即返回(只 L0–L3.5) | **否** | 是(后台完成) | ✅ + `DLP_USE_BEDROCK_L4=true` ⚠出 VPC |
| `sync` | 带墙钟等 L4 | 是(≥`DLP_L4_BLOCK_MIN_CONFIDENCE`→BLOCK) | 是 | — |

- **sink 脱敏**:JSONL 只出 `ts/kind(=l4_alert)/mode/category/confidence/model`,外加可选 `rationale[:200]`(由 `DLP_L4_SINK_RATIONALE` 门控,默认 `true`——⚠ Bedrock 自由文本 rationale 可能回显输入片段,知情接受;置 `false` 为严档零回显),**绝不落 `context`(原文片段)/matched/span/原始 body**。
- **sync 超时降级(Q3-b)**:超 `DLP_L4_TIMEOUT_MS` → 不 cancel future(后台跑完仍补落 sink)、响应按 L0–L3.5 **放行**,L4 超时**绝不阻断合法请求**。
- ⚠ **committed 演示默认 `async`+Bedrock=内容出 VPC**,是**知情的演示/标定 shipped default**,刻意违反下方红线;生产**必须** `DLP_USE_BEDROCK_L4=false` 切自托管 VPC-local(GPU+vLLM)。config/compose/启动日志/文档多处刺眼标注。

> **红线(保留):L4 语义模型生产必须本地自建或部署在自有 VPC 内。** 用第三方托管 LLM 审查外发内容 = 把要保护的内容再发出去一次,是第二条泄漏通道。上述 Bedrock 默认仅为**打开即可端到端验证功能**的演示例外,非生产配置。

---

## 6. MCP / 嵌套展开(`dlp/extract.py`)

- 输入 dict 形如 `{"tool":"write_file","arguments":{...}}`。
- **递归展开** `arguments` 的所有**字符串叶子**(对象+数组,不限深度,EVA-09 埋 5 层 + 数组下标)。
- 每个叶子带 `field_path`:点号 + 下标,如 `content` / `headers.Authorization` / `body.meta.debug.env[1].v`。
- **headers 全键值都扫**(MCP-05 定位 `headers.Authorization`,不止 body/url)。
- 同义工具名归一(`write_file`/`create_file`/`edit_file` → 同一处理;MCP-01)。
- MCP 参数里的 base64/hex 也走 `expand()` 解码回扫(EVA-17)。
- **egress/通道类**(套件4:shell.exec/git push/curl/execute_sql/code_search remote)由**通道管控子模块** `dlp/egress.py` 判定:识别 `read-then-exfil`(cat|curl、`-d @file`、`--data-binary @`)、`$VAR`/`${VAR}` 解引用、git push 非白名单 remote、execute_sql connection 不在 allowlist、code_search `remote:true`。命中→ `Hit(layer=L0, entity="EGRESS_*", action=BLOCK, ...)` 并在 notes 注明"通道管控兜底,非内容命中"。此为 default-deny 语义的引擎侧模拟。

---

## 7. fixture schema(`tests/fixtures/*.json`)—— 重建 56 条的格式

每套件一个 JSON 文件(`suite1.json`…`suite6.json`),数组,每条:

```json
{
  "id": "L0-02",
  "suite": 1,
  "injection_point": "prompt",
  "content": "<逐字输入;prompt/flowback 为 str,mcp 为对象>",
  "content_kind": "text | mcp_call",
  "session_window": null,
  "expected": {
    "verdict": "redact",
    "top_layer": "L0",
    "must_hit": [
      {"entity": "CN_ID_CARD", "action": "redact"},
      {"entity": "CN_PHONE", "action": "redact"}
    ],
    "must_not_hit": [],
    "async_l4_category": null
  },
  "invariants": ["身份证过 mod-11", "手机匹配 1[3-9]\\d{9}"],
  "verify_point": "身份证含校验命中、手机命中,动作 redact 非 block;姓名交 L3",
  "notes_expected": []
}
```

- `content` 为 `mcp_call` 时形如 `{"tool":"write_file","arguments":{"path":"cfg.py","content":"AKIA..."}}`。
- `expected.verdict`/`top_layer`/`must_hit[].entity+action` 是**断言的核心**;`must_not_hit` 用于套件2 的贴边负例(如"AKIA 示例值 must_not_hit AWS_ACCESS_KEY-block")。
- **套件6**:`expected.verdict` 恒 `pass`,`async_l4_category` 填 `proprietary-source`/`proprietary-business-logic`(仅 run_async_l4 时验)。
- **套件4**:`injection_point:"mcp"` 且期望由 `dlp/egress.py` 给出 `EGRESS_*` BLOCK;`verify_point` 写明"通道管控口径"。
- `invariants`:重建输入时必须构造成立的硬性质(mod-11 通过/不通过、Luhn 通过、base64 解出目标值、熵高/低、PEM 头类型、占位符字样)。**对抗审计(任务6)据此校验 fixture 正确性**。

---

## 8. 离线 harness(`tests/run_offline.py`)输出格式

- 载入 6 套件 fixtures,对每条 `engine.scan(content, injection_point=..., session_window=...)`(套件6 传 `run_async_l4=True`)。
- 比对:`verdict==expected.verdict` ∧ `top_layer==expected.top_layer` ∧ 每个 `must_hit` 都在 `result.hits`(entity+action 匹配) ∧ 无 `must_not_hit`。
- 输出**矩阵**:每条一行 `id | suite | 期望 | 实际 | ✓/✗ | top_layer | latency_ms | 命中规则`;末尾按套件汇总通过率 + 套件2 误报数(必须 0)+ 套件1 漏拦数(必须 0)。
- **不手写实测数字**;矩阵即实测。失败项打印 `hits` 详情便于定位。

---

## 9. 运行形态(Docker,合规)

- 镜像在 **`jumphost`(x86_64,与 kiro-dlp 同架构)构建**,`docker save | ssh kiro-dlp docker load`,在 **kiro-dlp `docker compose up`** 跑。
- compose 两服务:`presidio-analyzer`(官方镜像,:5002)+ `dlp-engine`(本工程,Py3.11)。
- 离线单测阶段:引擎可先在 kiro-dlp 直接跑(容器内),Presidio 不可达时按 §5-L3 的"缺席标注"处理,不阻塞套件1/2(它们主要靠 L0/L1/L2/L3.5)。
