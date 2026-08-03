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

## 阅读顺序

| # | 文档 | 给谁看 |
|---|---|---|
| 1 | [01-方案介绍-宣传.md](01-方案介绍-宣传.md) | 决策者 —— 场景、能力矩阵、按威胁模型选路径的决策清单 |
| 2 | [02-技术博客.md](02-技术博客.md) | 工程师 —— 第一性原理、两套方案的协议细节、CA 硬门槛、合规风险 |
| 3 | [03-方案一测试方案.md](03-方案一测试方案.md) | 想复核数字的人 —— 方案一四阶段实测方法与完整矩阵 |
| 4 | [方案二-selective-bump-mitm/README.md](方案二-selective-bump-mitm/README.md) | 方案二的设计 / 部署 / 测试三件套入口 |

## 目录结构

| 路径 | 内容 |
|---|---|
| [`engine/`](engine/) | 分层 DLP 引擎 L0–L4（正则 → detect-secrets → 熵 → Presidio → 术语表/EDM → 异步本地 LLM）＋ [`SPEC.md`](engine/SPEC.md) ＋ 测试与 fixture |
| [`gateway/`](gateway/) | 方案一：LiteLLM 网关配置、DLP guardrail（`pre_call_hook` / `pre_mcp_call`）、端到端与压测脚本 |
| [`docker/`](docker/) | 引擎 / Presidio 中文 NER / 网关的镜像与 compose |
| [`testing/`](testing/) | 方案一实测：探针、远程执行脚本、[`results-2026-07-30/`](testing/results-2026-07-30/) 原始输出 |
| [`方案二-selective-bump-mitm/`](方案二-selective-bump-mitm/) | 方案二全套：nginx `ssl_preread` SNI 选择性 bump、mitmproxy addon、三级 CA（带 Name Constraints）、部署/拆除脚本、四层测试 |

## 实测状态

**方案一已完成**（2026-07-30，us-west-2 真实单机 m7i.2xlarge）：离线 56/56、网关端到端 46/46，
漏拦 0 / 误报 0；DLP 同步扫描 p50≈28ms / p95≈53ms。**诚实标定**：~2000 token 长文本高并发下
单副本 Presidio 单核打满，p50 劣化到 7.4s —— 属部署配置问题，长文本生产须多 worker 扩容。
完整矩阵见 [03-方案一测试方案.md](03-方案一测试方案.md) §8。

**方案二实现完成、端到端实测待补**。在实测数据落地前不提供任何未经测量的数字。

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
