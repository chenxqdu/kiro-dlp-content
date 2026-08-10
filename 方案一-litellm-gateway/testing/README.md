# 方案一测试复现手册（testing/）

本目录汇总 2026-07-30 四阶段实测 + 2026-08-04 阶段5 分层完备测试 + 2026-08-05 阶段5 按当前引擎重跑用到的
**全部脚本、执行方法与原始输出**，供复现验证与分析。
实测结论与完整矩阵见 [../方案一-03-测试方案.md](../方案一-03-测试方案.md) §8；本 README 只讲"怎么跑出来的、怎么再跑一遍、结果怎么读"。

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
│   ├── host_stage4_l4.sh      阶段4：L4 Bedrock 标定（直连 + 端到端 + 还原开关）
│   └── host_stage5_layers.sh  阶段5：分层完备测试（Presidio 全量 + L3 隔离 + L4 --bedrock）
├── probes/                    ← 诊断探针（排障/根因分析）
│   ├── probe_presidio_raw.py       取 Presidio 原始 NER 输出（绕过引擎过滤）
│   ├── probe_presidio_variants.py  按引擎变体展开逐变体×逐语言归因误报
│   └── test_l3_weak_ner_replay.py  本地 mock 回放回归（不依赖实例，秒级）
├── results-2026-07-30/        ← 四阶段原始实测输出（未加工，含失败轮次）
├── results-2026-08-04/        ← 阶段5 分层完备测试原始输出（人工转录压缩版）
└── results-2026-08-05/        ← 阶段5 按【当前引擎】重跑 + 与 08-04 逐条 DIFF（逐字节原文）
```

测试代码本体在仓库其它目录（本目录的脚本调用它们）：

| 文件 | 作用 |
|---|---|
| [engine/tests/run_offline.py](../../engine/tests/run_offline.py) | 阶段1 离线 harness：56 条 → `engine.scan()`，判定 verdict/top_layer/must_hit/must_not_hit，硬门=套件1 漏拦0 + 套件2 误报0 |
| [engine/tests/fixtures/suite1..6.json](../../engine/tests/fixtures/) | 56 条测试语料（六套件，schema 见 engine/SPEC.md §7） |
| [engine/tests/fixture_invariants_check.py](../../engine/tests/fixture_invariants_check.py) | fixture 静态不变量校验器（改语料后先跑它） |
| [engine/tests/l4_calibration.py](../../engine/tests/l4_calibration.py) | 阶段4 L4 双模型标定（Qwen3-32B main / Llama-3.1-8B control） |
| [engine/tests/run_layers.py](../../engine/tests/run_layers.py) | 阶段5 分层 harness：直接调每层 `scan()`（不经引擎聚合），验每条规则的正例/豁免/边界；L3 缺 Presidio 自动 SKIP，L4-Bedrock 需 `--bedrock` |
| [engine/tests/fixtures_layers/](../../engine/tests/fixtures_layers/) | 阶段5 分层向量 78 条（l0/l1/l2/l3/l35/egress/norm/l4 八文件，schema 见 run_layers.py 头注释） |
| [engine/tests/_probe_layers.py](../../engine/tests/_probe_layers.py) | 阶段5 落笔前 oracle 探针：生成魔法值（mod-11 身份证/base64/hex/熵）+ 打印每层 scan() 真实命中，**所有向量断言据此实测输出写成，非臆断** |
| [engine/tests/inspect_cases.py](../../engine/tests/inspect_cases.py) | **逐条三合一检视器（只读）**：把 56/78 用例的「输入原文 + 效果(裁决/脱敏) + 分层延迟」拼成逐条卡片；本地 `scan()` 或 `--via-http` 打方案二 `/inspect`；`--format md/jsonl` 归档。跨方案统一用法见 [00-总览/03-手动复现指南-逐条三合一.md](../../00-总览/03-手动复现指南-逐条三合一.md) |
| [gateway/test_gateway.py](../gateway/test_gateway.py) | 阶段2 网关 harness：fixture → /chat/completions，block→400 / redact/pass→200 |
| [gateway/bench_gateway.py](../gateway/bench_gateway.py) | 阶段3 压测：3 payload × 4 并发档 × n=30，输出 JSON 行 |
| [gateway/dlp_guardrail.py](../gateway/dlp_guardrail.py) | 被测对象：LiteLLM CorpDLPGuardrail（两 hook） |

## 环境前提

- **实例**：`kiro-dlp` = `<TEST_INSTANCE_ID>`（m7i.2xlarge, us-west-2, profile `default`）。
  **无 SSH key，只能走 SSM**（实例须 SSM Online；本机 aws CLI 有 `ssm:SendCommand` 权限）。
- **实例上已就绪**：`/home/ec2-user/kiro-dlp/{engine,gateway,docker}`；容器
  `litellm`(:4000, DLP on)、`litellm-nodlp`(:4001, 对照)、`presidio-analyzer`(内网:5002, en_core_web_lg + zh_core_web_sm)；
  镜像 `kiro-dlp-engine:latest`。compose 定义在 [docker/](../../docker/)。
- **Bedrock**（仅阶段4）：实例 IAM 角色带 `bedrock:InvokeModel`（qwen.qwen3-32b-v1:0 / meta.llama3-1-8b-instruct-v1:0），IMDS hop-limit=2。

## 复现步骤（按阶段）

所有 `host_*.sh` 都经 `ssm_exec.sh` 投递到实例执行：

```bash
cd testing/remote
./ssm_exec.sh host_stage1_offline.sh          # 阶段1，约 30s
./ssm_exec.sh host_stage2_gateway.sh 900      # 阶段2，约 1 分钟
./ssm_exec.sh host_stage3_bench.sh 1800       # 阶段3，约 5 分钟（long-text 档慢）
./ssm_exec.sh host_stage4_l4.sh 900           # 阶段4（含还原 DLP_L4_BEDROCK=0）
./ssm_exec.sh host_stage5_layers.sh 900       # 阶段5 分层完备（含 L4 --bedrock 段）
```

`ssm_exec.sh` 与 `sync_engine.sh` 需要两个环境变量（不硬编码实例/桶）：

```bash
export KIRO_DLP_INSTANCE=<实例ID>
export KIRO_DLP_S3_BUCKET=<自有中转桶>
```

阶段5 也可先在本地空跑（无 Presidio/Bedrock，L3 与 L4-BR 向量自动 SKIP，其余 65 条应全绿）：

```bash
cd engine && python3 -m tests.run_layers --no-color
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
- 阶段5 期望三段全绿：②带 Presidio `74/78 fail=0 skip=4`（4 条 Bedrock 向量按设计 SKIP）`LAYERS_EXIT=0`；②b `L3 9/9` `L3_EXIT=0`；③ `--bedrock 8/8` `L4_BEDROCK_EXIT=0`。L3 单条 ~12–15ms 属正常（Presidio HTTP 往返）。

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
   > ⚠️ **这条清理会跨方案杀服务（2026-08-05 亲踩）**：`--filter ancestor=` 匹配的是**镜像**，而方案二的常驻
   > `kiro-dlp-http`（`:9000` inspect 服务）**跑的正是同一个 `kiro-dlp-engine:latest`**——于是
   > [`host_stage5_layers.sh:15`](remote/host_stage5_layers.sh) 会把它一并 `rm -f`。症状是方案二验证节点上
   > `curl 172.31.27.174:9000` 变成 `Failed to connect`，而**方案一自己的测试全绿、毫无异常**，极易漏判。
   > 复原（在 DLP 主机上）：
   > ```
   > cd /home/ec2-user/kiro-dlp && sudo docker compose -f docker-compose.dlp-http.yml up -d
   > ```
   > 复原后必须复核三件事：`/health` 返回 `{"status":"ok","engine":"ready"}`、容器内 L4 五个 env 仍在
   > （`DLP_RUN_ASYNC_L4`/`DLP_L4_SYNC_BLOCK`/`DLP_USE_BEDROCK_L4`/`DLP_L4_MODEL_KEY`/`DLP_L4_BLOCK_MIN_CONFIDENCE`）、
   > 经 `/inspect` 打一轮三态自检。**方案二在跑（或将要跑）时，别在同一台主机跑阶段5。**
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

## results-2026-08-04/ 原始输出索引

| 文件 | 内容 | 状态 |
|---|---|---|
| `stage5_layers_78.txt` | 阶段5 分层完备测试三段全量（Presidio 全量 74/78 + L3 隔离 9/9 + `--bedrock` 8/8） | ✅ 三段 exit=0 |

## results-2026-08-05/ 原始输出索引

| 文件 | 内容 | 状态 |
|---|---|---|
| `stage5_layers_78_rerun.txt` | 阶段5 **按当前引擎重跑**（含 `4f155bd` 引入的 `l4_sync_block` + 全角 `×`）三段全量，**逐字节 stdout 原文** | ✅ 三段 exit=0（74/78 skip=4 / L3 9/9 / L4-BR 8/8） |
| `DIFF-vs-2026-08-04.md` | 与 08-04 那轮**逐条比对**：版本对齐（三份 sha256）、段②78 vs 78 + 段③8 vs 8、层/状态差异 = **零**、归档形态差异说明、覆盖缺口 | ✅ 无回归 |
| `cleanup_filter_fix_verification.txt` | 已知坑 #1 修正的**真机验证**（只读探针：同时跑旧/新写法的选择逻辑，证明旧写法确实命中 `kiro-dlp-http`、新写法命中为空） | ✅ 修正生效 |

**为什么要重跑**：08-04 那轮跑在 `7333451`，之后 `4f155bd` 改了引擎（`engine.scan()` 加 L4 同步阻断、
`l4_semantic` 加全角 `×` 加权系数识别）。重跑前先探 sha256 证明实例上的 `engine.py`/`l4_semantic.py`/`server.py`
与本地逐字节一致（故**故意不跑 `sync_engine.sh`**，避免引入无关变更），再跑——所以这轮确实打的是当前引擎。

> ⚠️ **「全绿」的准确含义**：78 条向量里**没有任何一条**覆盖 `4f155bd` 的两项新行为——
> `l4_sync_block` 在 `engine.scan()` **聚合层**，而 `run_layers.py` 直调各层 `scan()`，**结构上到不了**（它属于
> `run_offline.py` 的辖区）；全角 `×` 则是 `l4.json` 里没有含 `×` 的语料。故重跑只证明
> **「新代码没打坏旧行为」**，不证明**「新行为正确」**。新行为的实证在别处：`l4_sync_block` 的真链路证据见
> 方案二 [Tier D 原始输出](../../方案二-selective-bump-mitm/results-2026-08-05/tier_d_relayer_layers.txt)
> 里 BLOCK 探针的 `notes=['L4 同步阻断(测试期/Bedrock)…']`。缺口的补法写在 DIFF 文档 §5。

**阶段5 与阶段1 的关系**：阶段1（`run_offline`）验的是"整机裁决"——56 条场景经 `engine.scan()` 全链路聚合出 verdict/top_layer；阶段5（`run_layers`）验的是"每层每条规则"——直接调 `l0_regex.scan()`/`l1_secrets.scan()`/… 逐规则断言正例、豁免（FP-01..12 白名单逐条独立成向量）、边界。阶段1 过不代表每条规则被触达（覆盖审计发现 L1 7 条签名、L3.5 5 条术语、EGRESS 全部变体在 56 条场景里为零覆盖），阶段5 补齐了这块。改任一层规则后两个 harness 都要跑。
