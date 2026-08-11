# 方案一 · opt-in LiteLLM TLS 终止网关 + VPC 内 DLP 联动

> **前提:客户端能改 `base_url`**(自研 Agent / SDK)。客户端主动把流量交到网关,
> 网关做 TLS 终止、成为**合法的明文终点** —— **无需伪造证书、无需分发企业 CA**。
> 这是干净的路径:能改 `base_url` 就别做中间人(那是[方案二](../方案二-selective-bump-mitm/)的活)。
>
> 网关内挂 `CorpDLPGuardrail`(LiteLLM 的 `pre_call_hook` + `pre_mcp_call` 两个钩子),
> 把 prompt / flowback / MCP 调用同步送共享 DLP 引擎裁决(`PASS / REDACT / BLOCK`),
> 内容全程不出 VPC。2026-07-30 在 us-west-2 单机(m7i.2xlarge)实测:离线 56/56、
> 网关端到端 46/46,漏拦 0 / 误报 0;2026-08-04 分层完备测试 78 条(每层每规则)三段全绿,
> 2026-08-05 按最新引擎重跑零差异。

---

## 📚 本目录内容

| 路径 | 作用 |
|---|---|
| [**方案一-01-设计与架构.md**](方案一-01-设计与架构.md) | 纲领:为什么 opt-in 网关而非 MITM(三条设计约束)、拓扑、组件职责、三注入点、fail 语义、9 条安全红线、与方案二对比、诚实边界 |
| [**方案一-02-部署指南.md**](方案一-02-部署指南.md) | 前置条件 → 密钥/环境纪律 → jumphost 构建镜像 → 实例扁平布局装配 → 网关启动 → 部署后自检 → 变更流 → 停服/拆除 |
| [**方案一-03-测试方案.md**](方案一-03-测试方案.md) | 四阶段实测方法与完整矩阵(离线 harness / 网关集成 / 压测归因 / L4 标定 / 分层完备)+ §8 全部实测数字 |
| [**方案一-04-实测踩坑实录.md**](方案一-04-实测踩坑实录.md) | 四阶段踩坑复盘(症状→证据→根因→修法):引擎弱 NER 误报、"某版本更绿"测量假象、孤儿抢核、Bedrock Converse 约束、长文本单核瓶颈、SSM 投递三坑、L4 红线还原 |
| [`gateway/`](gateway/) | 网关本体:[`litellm_config.yaml`](gateway/litellm_config.yaml)(挂 guardrail)、[`dlp_guardrail.py`](gateway/dlp_guardrail.py)(`CorpDLPGuardrail`,两 hook)、[`test_gateway.py`](gateway/test_gateway.py) 端到端、[`bench_gateway.py`](gateway/bench_gateway.py) 压测、`litellm_config_nodlp.yaml` 对照组 |
| [`testing/`](testing/) | 实测复现三件套:[README](testing/README.md)(怎么跑)、`remote/`(SSM 远程执行脚本)、`probes/`(诊断探针)、`results-2026-07-30/` + `results-2026-08-04/` + `results-2026-08-05/` + `results-2026-08-10/`(原始输出,含失败轮次、逐条 DIFF 与 `perf/` k6 压测) |

## 🔗 依赖的共享组件(在仓库根,不在本目录)

| 路径 | 为什么在根 |
|---|---|
| [`../engine/`](../engine/) | 分层 DLP 引擎 L0–L4 —— **两个方案共用**。本方案的 `dlp_guardrail.py` `import dlp.engine`;方案二的判定服务也 import 它。改引擎一处,两方案同时受益。 |
| [`../docker/`](../docker/) | 镜像与 compose。base [`docker-compose.yml`](../docker/docker-compose.yml)(引擎 + Presidio 中文 NER)两方案共用;本方案的网关叠加层 [`docker-compose.gateway.yml`](../docker/docker-compose.gateway.yml) 是它的 override,须与 base 同处 `docker/`(Docker 规则:override 的相对路径按 base 目录解析)。 |

## 🚀 部署与测试(在 kiro-dlp 实例上,经 SSM)

实例布局扁平:`/home/ec2-user/kiro-dlp/{engine,gateway,docker}`(由 `testing/remote/` 的 sync 脚本拼装,与仓库目录结构解耦)。

```bash
# 启动网关(base + 网关叠加层,两 compose 同处 docker/)
cd /home/ec2-user/kiro-dlp/docker
docker compose -f docker-compose.yml -f docker-compose.gateway.yml up -d presidio-analyzer litellm
```

完整复现步骤(五阶段、判读标准、已知坑)见 [testing/README.md](testing/README.md);实测结论见 [方案一-03-测试方案.md](方案一-03-测试方案.md) §8。

## 方案一 vs 方案二

| | 方案一(本目录) | [方案二](../方案二-selective-bump-mitm/) |
|---|---|---|
| 触发前提 | 客户端**能改** `base_url` | 客户端**不能改**(闭源工具,端点硬编码) |
| 明文获取 | TLS 终止(合法终点) | 选择性 bump MITM(冒充域名) |
| 企业 CA | **不需要** | 必须自建三级 CA + 分发根证书 |
| 代价 | 干净,低 | 有真实代价(证书信任、协议脆弱性) |
| 共用 | 同一个 [`../engine/`](../engine/) DLP 引擎 | 同左 |

> 一句话:**能改 `base_url` 就走方案一,别做中间人。** 决策清单见 [00 总览](../00-总览/01-方案介绍-宣传.md)。
