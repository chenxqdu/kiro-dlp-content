<!-- Copyright (c) 2026 Amazon.com and Affiliates. -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 方案二 `/inspect` 压测资产

对应 [方案二-03-测试报告.md](../../方案二-03-测试报告.md) **§8 压测**:负载下拦截正确性 + 基准延迟分位。
方法学移植自 [方案一 03 §9](../../../方案一-litellm-gateway/方案一-03-测试方案.md)（open-loop
`constant-arrival-rate`，避免 coordinated omission），断言口径按 `/inspect` 契约改写。

> **状态（2026-08-11 已跑）**：B/A/C/D 四实验实测完成，分位/吞吐数字回填至方案二-03 **§8**，
> 原始 k6 输出归档 [`../../results-2026-08-11/perf/`](../../results-2026-08-11/perf/)
> （`k6_*.txt` + `summary_*.json`）。本目录脚本可复跑；数字一律取自机器输出，无手写。

## 与方案一 perf 的本质差异（决定断言口径）

方案二被测对象是 **`/inspect` 纯裁决薄服务**（`http_service/server.py`）——**不转发上游、不接 LLM**，
恒返回 `HTTP 200 + verdict JSON`（错误路径才 503/413/400）。由此两点与方案一不同：

1. **拦截判据看返回 JSON 的 `verdict`**（`BLOCK`/`REDACT`/`PASS`），不是方案一的 HTTP 400。
   测的是**引擎裁决延迟本身**，不含网关 + 假上游成本 → 比方案一更纯，故**无假上游、无 litellm 配置切换**两步。
2. **泄漏语义按真实 MITM 数据流判定**（addon 依 verdict 决定写什么给上游）：
   - `verdict==BLOCK` → addon 短路不发上游 → 绝不泄漏（正确）
   - `verdict==REDACT` → addon 把 `redacted_body` 写回上游 → 泄漏 **iff** 脱敏体仍含明文探针
   - `verdict==PASS`（攻击向量被放行）→ addon 转发**原始明文** → 泄漏
   唯一失败态 = 攻击向量的原始敏感明文会流向上游。`plaintext_leak` 计数必须 = 0。
3. **契约哨兵**：响应体绝不含 `matched`/`span`（`server._safe_rules` 已剥离）；k6 额外做 `contract_leak` 回归断言。

## 文件清单

| 文件 | 作用 |
|---|---|
| `vectors.json` | 攻击/合法向量库。与方案一 `testing/perf/vectors.json` 同 schema、同引擎裁决（共享 `engine/dlp`），故向量原样对齐；分 `attack_local_block`/`attack_local_redact`（本地层，对过载鲁棒）、`attack_l3only`（仅 Presidio，过载/停 Presidio 探针）、`legal_short`。合成/公开示例串，非真实凭证。 |
| `inspect_perf.js` | k6 主脚本。`EXP=A/B/C/D` 选实验；自定义指标按处置路径分开延迟（`inspect_block_ms`/`inspect_redact_ms`/`inspect_pass_ms`），并抓 `plaintext_leak`（必须=0）、`legal_false_positive`（误杀率）、`forced_block`（fail-closed 计数）、`contract_leak`（必须=0）。 |
| `run_inspect_perf.sh` | 一键 runner：`GET /health` 探活 → 冒烟三态（curl `/inspect` 看 verdict + LEAK-CHECK）→ 按 EXP 跑 k6 → 归档 k6 summary + 快照。**无假上游/无配置切换**（`/inspect` 不转发）。 |

## 四个实验

| 实验 | 负载 | 测什么 | 判据 |
|---|---|---|---|
| **B** | 纯合法阶梯加压 | `/inspect` 最大可检吞吐（拐点）、负载下误杀率 | 误杀率=0 |
| **A** | 纯攻击「打满不排队」 | 处置率上限 + 三路径延迟分位数 | BLOCK 100%；Presidio 健康时 REDACT 100% |
| **C** | 合法背景 + 定速攻击注入 | 负载下拦截率（k6 check 双源对账） | 本地类 100%；L3 类看退化 |
| **D** | 长文本压 Presidio 过载 + 两类攻击 | **fail-closed 行为**：L3-only 过载/停 Presidio 下的处置分布 | 本地类 100%；**明文泄漏率=0**（L3 不可达→`forced_block=l3_unavailable`+BLOCK，非静默 PASS） |

## 执行

拓扑（方案一 §9.5）：**首选**发压机与被测机分离——在发压机（如 MITM 验证节点 arm64）跑，
`DLP_URL` 指向 gateway 主机私网 `:9000`；**次选**同机——在 gateway 主机跑，`DLP_URL=127.0.0.1:9000`，
`TASKSET_CPUS` 把 k6 与被测容器分核（尾延迟含抢核噪声，如实标注）。

```bash
# 发压机上（须能访问 DLP :9000）
export DLP_URL=http://172.31.27.174:9000      # 分离部署；同机则 127.0.0.1:9000
bash run_inspect_perf.sh smoke                # 先冒烟（/health + 三态 + LEAK-CHECK）
bash run_inspect_perf.sh all                  # 顺序 B→A→C→D
# 单跑并调参：
bash run_inspect_perf.sh D BG_RATE=30 ATK_RATE=5 DURATION=120s LONGTOK=2500
# 次选同机绑核：
TASKSET_CPUS=0,1 bash run_inspect_perf.sh A
```

结果落 `results-<date>/`：`k6_<EXP>.txt`、`summary_<EXP>.json`（HDR 直方图）、`stats_<EXP>.txt`。

> ⚠ **跨方案清理红线**：压测期间**绝不在 gateway 主机跑方案一 stage5**——它用
> `--filter ancestor=kiro-dlp-engine:latest` 清孤儿容器，会把正被压测的 `kiro-dlp-http`
> 一并 `rm -f`（同一镜像）。详见方案一 `testing/README.md` 已知坑 #1。

## 诚实边界

1. 门槛是**期望**，实测可能推翻；数字未经实例真跑不得写入。
2. `/inspect` 延迟是**引擎裁决净成本**，**不含 MITM 真链路的 TLS 劫持 + 转发上游**——那部分是
   Tier D 的**定性**证据（`verdict`+`top_layer` 双断言），不是分位数。
3. 单副本 Presidio 单核瓶颈（承接方案一 §8.6）：长文本高并发下 L3 会成为吞吐上限。
4. 次选同机部署含负载生成器抢核噪声，尾延迟偏高；拦截正确性结论（泄漏=0/误杀=0）不受影响。
