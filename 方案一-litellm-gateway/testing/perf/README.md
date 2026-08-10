<!-- Copyright (c) 2026 Amazon.com and Affiliates. -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 阶段6 性能测试资产(方案一网关)

对应 `方案一-03-测试方案.md` **§9**:拦截成功率 + 压测下拦截延迟。open-loop
(k6 constant-arrival-rate)度量,避免 coordinated omission;双数据源对账
(客户端 check ⊕ 网关 metrics jsonl)。

> **状态**:方法与脚本已就绪。实测数字在 `kiro-dlp` 实例真跑后按 §8 体例回填,
> 本目录不含任何手写数字。

## 文件清单

| 文件 | 作用 |
|---|---|
| `fake_upstream.py` | 假上游(§9.3 法1):OpenAI `/chat/completions` 兼容 echo 端点,纯 stdlib。把上游生成延迟从测量剔除;**回显收到的(可能已脱敏的)输入**,使客户端能验证 REDACT 是否真生效。 |
| `vectors.json` | 攻击/合法向量库(§9.1.1),分 `attack_local_block`/`attack_local_redact`(本地层,对过载鲁棒)、`attack_l3only`(仅 Presidio,过载探针)、`legal_short`。取自已验证的 `fixtures_layers/{l0,l3}.json`。 |
| `dlp_perf.js` | k6 主脚本。`EXP=A/B/C/D` 选实验;自定义指标按处置路径分开延迟(BLOCK/REDACT/PASS),并抓 `plaintext_leak`(明文泄漏,必须=0)与 `legal_false_positive`(误杀率)。 |
| `litellm_config_perf.yaml` | perf 版 litellm 配置:在阶段2 基础上加 `echo-fast` 模型指向假上游;guardrails 与阶段2 完全一致。 |
| `docker-compose.perf.yml` | compose override:给 litellm 容器加 `host.docker.internal`(访问宿主假上游)+ 换 perf 配置。 |
| `run_perf.sh` | 一键 runner:起假上游 → 切 perf 配置 → 冒烟三态 → 按 EXP 跑 k6 → 归档 `docker stats`/`mpstat` 快照 + k6 summary。 |

## 四个实验(§9.7)

| 实验 | 负载 | 测什么 | 判据 |
|---|---|---|---|
| **B** | 纯合法阶梯加压 | 95% 最大可检吞吐(作 C 背景速率)、负载下误杀率 | 误杀率=0 |
| **A** | 纯攻击「打满不排队」 | 处置率上限 + 三路径延迟分位数 | BLOCK 100%;Presidio 健康时 REDACT 100% |
| **C** | 合法背景 + 定速攻击注入 | 负载下拦截率(双源对账) | 本地类 100%;L3 类看退化 |
| **D** | 长文本压 Presidio 过载 + 两类攻击 | **fail-closed 行为**:L3-only 过载下的处置分布 | 本地类 100%;**明文泄漏率=0**(L3 过载→强制 BLOCK,非静默 PASS) |

> **实验 D 的语义(fail-closed 版)**:网关现读 `notes` 强制升级(规格 D4),故
> Presidio 过载时 L3-only 向量的正确行为是 **200+脱敏成功 或 400 forced_block**,
> 泄漏率必须为 0。对照旧 fail-open 行为可 `export DLP_L3_UNAVAILABLE_ACTION=keep`
> 复现「静默 PASS 明文泄漏」,直接量化两种策略差异。

## 执行(在 kiro-dlp 实例上)

```bash
# 1) 同步资产 + fail-closed 网关代码到实例(本机执行)
KIRO_DLP_S3_BUCKET=<你的中转桶> ./testing/remote/sync_gateway_perf.sh

# 2) 实例上(经 SSM)执行
export LITELLM_MASTER_KEY=<与在跑 litellm 一致>
bash testing/perf/run_perf.sh smoke     # 先冒烟
bash testing/perf/run_perf.sh all       # 顺序 B→A→C→D
# 或单跑并调参:
bash testing/perf/run_perf.sh D BG_RATE=30 ATK_RATE=5 DURATION=120s LONGTOK=2500
```

结果落 `testing/perf/results-<date>/`:`k6_<EXP>.txt`、`summary_<EXP>.json`
(HDR 直方图)、`stats_<EXP>.txt`、`mpstat_<EXP>.txt`。

## 诚实边界(§9.8)

1. 门槛是**期望**,实测可能推翻;数字未经实例真跑不得写入。
2. 单机合并部署含噪声(litellm/engine/presidio/负载生成器抢核),已尽量绑核。
3. metrics 对账是**计数级、非逐条**(jsonl 无 request id)。
4. 假上游 ≠ 真实上游延迟:本节延迟是**网关侧净成本**,不含模型生成时间。
