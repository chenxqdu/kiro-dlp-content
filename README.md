# 企业 AI 数据防泄漏方案（AI 编码工具场景）

研发开始用 AI 写代码之后，数据外泄的形态变了：泄漏不再发生在文件外传或 U 盘拷贝里，
而发生在一条条到大模型域名的、加密的、看起来完全正常的 HTTPS 连接里。本仓库是对这个问题
的一次完整梳理 —— 设计、实现、实测，以及**兜不住的盲区**。

## 核心论点

**一、先分清三类诉求**，缓解手段完全不同：

| 诉求 | 最有效的手段 |
|---|---|
| 防训练 / 防留存 | **合同**（IdC 企业版 opt-out），不是技术 |
| 防误贴 / 防外发 | 内容型 DLP —— 本仓库主体 |
| 防出境 | Kiro **从根上满足不了**（无中国区），DLP 只降低不消除 |

**二、内容审查只能发生在能拿到明文的点**，所以决定性变量只有一个 ——
**客户端能不能改 `base_url`**：

- **能改**（自研 Agent / SDK）→ **方案一**：opt-in 的 LiteLLM TLS 终止网关。客户端主动把流量
  交过来，网关是合法明文终点，**无需伪造证书、无需分发企业 CA**。干净的路径。
- **不能改**（闭源工具，端点硬编码）→ **方案二**：选择性 bump MITM。只能冒充那个域名，
  这是有真实代价的路径。**能改 `base_url` 就别做中间人。**

**三、内容型 DLP 是 best-effort 检知，不是硬预防。扫描通过 ≠ 无泄漏。**
一段内容是否属于「本公司机密」往往无法仅凭内容本身判断 —— 对已登记指纹强，
对新写的源码系统性漏检。**多数公司的多数威胁模型停在「合同 + default-deny 出口白名单」
就已经解决，走不到 MITM 这一步。**

## 仓库怎么组织的

三层，各司其职 —— **整体思路** / **共享实现** / **两个方案各自的实现·部署·测试**：

```
kiro-dlp-content/
├── 00-总览/                      整体思路与方案介绍（两方案共用，先读这里）
│   ├── 01-方案介绍-宣传.md          决策者视角：场景、能力矩阵、按威胁模型选路径
│   └── 02-技术博客.md               工程师视角：第一性原理、两方案协议细节、CA 硬门槛
│
├── engine/    ★共享             分层 DLP 引擎 L0–L4 —— 两个方案都 import 它
├── docker/    ★共享             引擎 / Presidio 中文 NER 镜像与 compose（含方案一网关叠加层）
│
├── 方案一-litellm-gateway/       【能改 base_url】opt-in TLS 终止网关（无需伪造证书）
│   ├── 方案一-01-设计与架构.md      纲领：为什么 opt-in 不 MITM、组件职责、安全红线
│   ├── 方案一-02-部署指南.md        镜像构建 → 扁平布局装配 → 网关启动 → 变更流/拆除
│   ├── 方案一-03-测试方案.md        四阶段实测方法与完整矩阵
│   ├── 方案一-04-实测踩坑实录.md     引擎弱 NER 误报、测量假象、压测归因、SSM/L4 纪律
│   ├── gateway/                   LiteLLM 配置、DLP guardrail、端到端与压测脚本
│   └── testing/                   实测:探针、远程执行脚本、results-* 原始输出
│
└── 方案二-selective-bump-mitm/   【不能改 base_url】选择性 bump MITM（有真实代价）
    ├── 方案二-01-设计与架构.md      02-部署指南 / 03-测试报告 / 04-真机踩坑实录
    ├── deploy.sh / gen-ca.sh / cleanup.sh / kiro_addon.py
    └── http_service/ + tests/     DLP 判定薄服务 + 四层测试
```

> **为什么 `engine/` 和 `docker/` 不塞进某个方案**：两套方案共用同一个 DLP 引擎和镜像 ——
> 方案一的 guardrail 与方案二的判定服务都 `import dlp.engine`。把共享层留在根、两个方案平级并列，
> 是最诚实的组织：改引擎一处，两方案同时受益，不会藏在任一方案目录里。

## 阅读顺序

| # | 文档 | 给谁看 |
|---|---|---|
| 1 | [00-总览/01-方案介绍-宣传.md](00-总览/01-方案介绍-宣传.md) | 决策者 —— 场景、能力矩阵、按威胁模型选路径的决策清单 |
| 2 | [00-总览/02-技术博客.md](00-总览/02-技术博客.md) | 工程师 —— 第一性原理、两套方案的协议细节、CA 硬门槛、合规风险 |
| 3a | [方案一-litellm-gateway/README.md](方案一-litellm-gateway/README.md) | 方案一：opt-in LiteLLM 网关 —— [设计与架构](方案一-litellm-gateway/方案一-01-设计与架构.md) / [部署指南](方案一-litellm-gateway/方案一-02-部署指南.md) / [测试方案](方案一-litellm-gateway/方案一-03-测试方案.md) / [实测踩坑实录](方案一-litellm-gateway/方案一-04-实测踩坑实录.md) 四件套 |
| 3b | [方案二-selective-bump-mitm/README.md](方案二-selective-bump-mitm/README.md) | 方案二：选择性 bump MITM —— 设计 / 部署 / 测试 / 真机踩坑四件套入口 |

## 共享组件

| 路径 | 内容 |
|---|---|
| [`engine/`](engine/) | ★两方案共享：分层 DLP 引擎 L0–L4（正则 → detect-secrets → 熵 → Presidio → 术语表/EDM → 异步本地 LLM）＋ [`SPEC.md`](engine/SPEC.md) ＋ 测试与 fixture |
| [`docker/`](docker/) | ★两方案共享：引擎镜像 `Dockerfile.engine`、Presidio 中文 NER `Dockerfile.presidio-zh`、base `docker-compose.yml`；方案一网关叠加层 `docker-compose.gateway.yml`（与 base 强耦合，须同处一目录：`-f docker-compose.yml -f docker-compose.gateway.yml`，override 相对路径按 base 目录解析） |

## 实测状态

**方案一已完成**（2026-07-30，us-west-2 真实单机 m7i.2xlarge）：离线 56/56、网关端到端 46/46，
漏拦 0 / 误报 0；DLP 同步扫描 p50≈28ms / p95≈53ms。**诚实标定**：~2000 token 长文本高并发下
单副本 Presidio 单核打满，p50 劣化到 7.6s —— 属部署配置问题，长文本生产须多 worker 扩容。
完整矩阵见 [方案一-03-测试方案.md](方案一-litellm-gateway/方案一-03-测试方案.md) §8，
四阶段踩坑复盘见 [方案一-04-实测踩坑实录.md](方案一-litellm-gateway/方案一-04-实测踩坑实录.md)。

**方案二真机端到端已完成**（2026-08-03，真实 Kiro 桌面端 → 验证节点选择性 bump → VPC 内
DLP → 真实上游）：三态全绿 —— PASS 正常回答 / REDACT 手机号链路遮蔽（工具目录与协议字段
逐字节完好）/ BLOCK 真密钥拦截。**合成测试全绿 ≠ 真机可用**：接入真实客户端后连翻三轮,
修复了六个"输入假设"级的坑（工具目录 L2 高熵误报、会话历史重扫、协议字段 NER 误判、
脱敏跨字段污染等），全程复盘见
[方案二-04-真机踩坑实录.md](方案二-selective-bump-mitm/方案二-04-真机踩坑实录.md)。

## 关于本仓库

- **这是内部工作材料**，不是 Amazon 发布的产品文档或官方立场，未授权对外分发。
- 仓库中**不含任何真实凭证**。所有密钥形状的字符串都是刻意合成的：
  `AKIAIOSFODNN7EXAMPLE` 是 AWS 官方公开示例值，[`engine/tests/fixtures/`](engine/tests/) 下
  的密钥、PII、PEM 均为 fixture 生成器造出来的合成数据（用于验证检出率），
  PEM 块全是占位符。扫描器如有告警，属预期误报。
- 真实基础设施 ID 不入仓：`config.env` / `.deploy-state.env` / `client-hosts.txt` 已 git-ignored，
  部署前 `cp config.env.example config.env` 填入自己的资源。
- [`方案二-selective-bump-mitm/root-ca-for-clients.crt`](方案二-selective-bump-mitm/root-ca-for-clients.crt)
  是**公钥根证书**（本就用于分发给客户端），不含私钥；CA 私钥只在 EC2 现场生成、不出机。
