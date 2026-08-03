# 方案一测试复现手册（testing/）

本目录汇总 2026-07-30 四阶段实测用到的**全部脚本、执行方法与原始输出**，供复现验证与分析。
实测结论与完整矩阵见 [../03-方案一测试方案.md](../03-方案一测试方案.md) §8；本 README 只讲"怎么跑出来的、怎么再跑一遍、结果怎么读"。

## 目录结构

```
testing/
├── README.md                  ← 本文件
├── remote/                    ← 远程执行脚本（本机发起，实例上跑）
│   ├── ssm_exec.sh            通用 SSM 执行器（base64 投递 + 轮询 + 取回输出）
│   ├── sync_engine.sh         同步本地 engine/ 到实例（S3 presigned URL 中转）
│   ├── host_stage1_offline.sh 阶段1：离线 56 条矩阵
│   ├── host_stage2_gateway.sh 阶段2：网关集成测 + 指标复核
│   ├── host_stage3_bench.sh   阶段3：开/关 DLP 压测 + docker stats 归因
│   └── host_stage4_l4.sh      阶段4：L4 Bedrock 标定（直连 + 端到端 + 还原开关）
├── probes/                    ← 诊断探针（排障/根因分析）
│   ├── probe_presidio_raw.py       取 Presidio 原始 NER 输出（绕过引擎过滤）
│   ├── probe_presidio_variants.py  按引擎变体展开逐变体×逐语言归因误报
│   └── test_l3_weak_ner_replay.py  本地 mock 回放回归（不依赖实例，秒级）
└── results-2026-07-30/        ← 本轮原始实测输出（未加工，含失败轮次）
```

测试代码本体在仓库其它目录（本目录的脚本调用它们）：

| 文件 | 作用 |
|---|---|
| [engine/tests/run_offline.py](../engine/tests/run_offline.py) | 阶段1 离线 harness：56 条 → `engine.scan()`，判定 verdict/top_layer/must_hit/must_not_hit，硬门=套件1 漏拦0 + 套件2 误报0 |
| [engine/tests/fixtures/suite1..6.json](../engine/tests/fixtures/) | 56 条测试语料（六套件，schema 见 engine/SPEC.md §7） |
| [engine/tests/fixture_invariants_check.py](../engine/tests/fixture_invariants_check.py) | fixture 静态不变量校验器（改语料后先跑它） |
| [engine/tests/l4_calibration.py](../engine/tests/l4_calibration.py) | 阶段4 L4 双模型标定（Qwen3-32B main / Llama-3.1-8B control） |
| [gateway/test_gateway.py](../gateway/test_gateway.py) | 阶段2 网关 harness：fixture → /chat/completions，block→400 / redact/pass→200 |
| [gateway/bench_gateway.py](../gateway/bench_gateway.py) | 阶段3 压测：3 payload × 4 并发档 × n=30，输出 JSON 行 |
| [gateway/dlp_guardrail.py](../gateway/dlp_guardrail.py) | 被测对象：LiteLLM CorpDLPGuardrail（两 hook） |

## 环境前提

- **实例**：`kiro-dlp` = `<TEST_INSTANCE_ID>`（m7i.2xlarge, us-west-2, profile `default`）。
  **无 SSH key，只能走 SSM**（实例须 SSM Online；本机 aws CLI 有 `ssm:SendCommand` 权限）。
- **实例上已就绪**：`/home/ec2-user/kiro-dlp/{engine,gateway,docker}`；容器
  `litellm`(:4000, DLP on)、`litellm-nodlp`(:4001, 对照)、`presidio-analyzer`(内网:5002, en_core_web_lg + zh_core_web_sm)；
  镜像 `kiro-dlp-engine:latest`。compose 定义在 [docker/](../docker/)。
- **Bedrock**（仅阶段4）：实例 IAM 角色带 `bedrock:InvokeModel`（qwen.qwen3-32b-v1:0 / meta.llama3-1-8b-instruct-v1:0），IMDS hop-limit=2。

## 复现步骤（按阶段）

所有 `host_*.sh` 都经 `ssm_exec.sh` 投递到实例执行：

```bash
cd testing/remote
./ssm_exec.sh host_stage1_offline.sh          # 阶段1，约 30s
./ssm_exec.sh host_stage2_gateway.sh 900      # 阶段2，约 1 分钟
./ssm_exec.sh host_stage3_bench.sh 1800       # 阶段3，约 5 分钟（long-text 档慢）
./ssm_exec.sh host_stage4_l4.sh 900           # 阶段4（含还原 DLP_L4_BEDROCK=0）
```

改了本地 `engine/dlp/*.py` 或 fixtures 之后，先同步再跑：

```bash
./sync_engine.sh
```

改动会影响网关行为时（guardrail 挂载的是 `/app/dlp` 源码），阶段2 前须在实例上
`sudo docker restart litellm`（`host_stage2_gateway.sh` 的注释里有说明）。

**判读**：
- 阶段1 期望 `56/56`、`FULL_EXIT=0`（exit 非 0 = 有 fail 或硬门破）。
- 阶段2 期望 `pass=46 fail=0`、`GW_EXIT=0`，且指标复核的 verdict 分布应为
  block 22（L0=16/L1=2/L2=1/L3.5=3）、redact 6（L0=5/L3.5=1）、pass 27。
- 阶段3 无硬门，比对 `results-2026-07-30/stage3_*` 的量级：dlp-off 全档 p50≈103–130ms；
  dlp-on 短文本 c1 p50≈152ms；**long-text c8+ p50 劣化到 7s+ 且 stats 里 presidio 单核打满是预期现象**（已知瓶颈，见 03 §8.3）。
- 阶段4 期望 main 4/4、`同步 verdict 污染: 0`、端到端 4×HTTP 200 + 3 条 l4_alert 落盘 + S6-04 无告警，收尾输出 `DLP_L4_BEDROCK=0`。

## 排障方法（本轮实际用过的分析路径）

**症状：某条 fixture verdict 不符且命中 `presidio:*`** → 三步归因：

1. `probes/probe_presidio_raw.py` —— 看 analyzer 原始 entity/score/片段（是不是 NER 报的）。
2. `probes/probe_presidio_variants.py` —— 按 raw/normalized/stripped-sep/decoded:* 逐变体归因（误报发生在哪个预处理上）。
   两个探针都在实例上以容器方式跑（文件头有完整 docker run 命令）。
3. 判定修引擎还是修语料：**本轮结论是修引擎**（Presidio 弱 NER 恒 0.85 分无从卡阈值，
   修复=合法性过滤+强实体佐证，详见 03 §8.1），**fixture 一字未动**。

**修复后的本地快速回归**（不依赖实例）：

```bash
python3 probes/test_l3_weak_ner_replay.py
```

用实测原始 NER 输出做 mock 回放，断言三条修复语义（S6-01 零命中 / S2-14 运单号钳制 / L3-09 多实体组合不回归）。

**离线单套件定位**：`host_stage1_offline.sh` 注释里的 `--suite N --verbose` 会对失败项打印每条 hit 的 layer/rule/entity/action/source。

## 已知坑（复现时必读）

1. **孤儿容器抢核**：`ssm cancel-command` 不杀容器；残留的 kiro-dlp-engine 容器会抢 presidio 单核，把延迟计时打飞到 14–29s/条。每次跑测前清理（host 脚本已内置）：
   `sudo docker ps -q --filter ancestor=kiro-dlp-engine:latest | xargs -r sudo docker rm -f`
2. **SSM 传参**：`--parameters` shorthand 对含空格/引号/中文的 commands 会 ValidationException。只能整体 base64（`ssm_exec.sh` 已封装）；大文件走 S3 presigned URL（`sync_engine.sh`）。
3. **SSM 会话结束杀后台进程**：`nohup ... &` 落盘 0 行。长任务前台跑 + 调大 `executionTimeout`。
4. **Bedrock Converse tool 序列三连约束**（阶段2 flowback 用例曾连栽两轮，均非 DLP 问题）：
   assistant.tool_calls 必须带 `tools=` 定义；tool result 不能与 user content 同轮（llama 严格、qwen 宽容）；`test_gateway.py` 的 `build_messages()` 已按此构造，勿"简化"。
5. **session_window 语义**：prompt 类 fixture 的 `session_window` 要作为前置 user 消息发送才能复现滑窗拼接（S5-04/S5-06 拆分密钥用例依赖此）。
6. **阶段4 红线**：Bedrock = 数据出 VPC，**仅功能验证非生产**；跑完必须还原 `DLP_L4_BEDROCK=0`（`host_stage4_l4.sh` 已内置还原步骤，最后一行输出须确认）。

## results-2026-07-30/ 原始输出索引

| 文件 | 内容 | 状态 |
|---|---|---|
| `stage1_offline_56x56.txt` | 阶段1 终版全量矩阵 | ✅ 56/56, exit=0 |
| `stage1_prefix_s6probe_suites1235_first_run.txt` | 修复前首轮：S6 hit 归因探针 + 套件1/2/3/5（**套件2 8/16 误报现场**） | 📌 修复依据 |
| `stage2_gateway_46x46_final.txt` | 阶段2 终版 + 指标复核（verdict 分布/p50/p95） | ✅ 46/46, exit=0 |
| `stage2_gateway_first_run_46pass_4fail.txt` | 首轮：S5 flowback 4 fail（缺 tool_calls 序列，坑 #4） | 📌 排障过程 |
| `stage2_gateway_second_run_44pass_2fail.txt` | 二轮：仍 2 fail（tool result 与 user 同轮，坑 #4） | 📌 排障过程 |
| `stage3_bench_dlpon_v2_dlpoff_stats.txt` | 阶段3 终版：dlp-on-v2 + dlp-off + stats 采样 | ✅ 全档 errs=0 |
| `stage3_bench_dlpon_prefix_engine.txt` | 修复前引擎的 dlp-on 基线（与 v2 对比：修复不影响性能） | 📌 对照 |
| `stage3_stats_prefix_run.txt` | 长文本负载下 stats（presidio ~100% 单核证据） | 📌 归因证据 |
| `stage4_l4_calibration.txt` | 阶段4 直连双模型标定矩阵 | ✅ main 4/4, exit=0 |
| `stage4_l4_e2e_gateway.txt` | 阶段4 端到端（同步 200 + l4_alert 落盘 + 日志） | ✅ |

> 失败轮次的输出**有意保留**：`stage1_prefix_*` 是"修引擎而非改语料"决策的原始证据；
> `stage2_*_first/second_run` 记录了 Bedrock tool 序列两个坑的真实报错，复现踩坑时先对照它们。
