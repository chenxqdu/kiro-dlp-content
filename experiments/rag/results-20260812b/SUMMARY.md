<!-- Copyright (c) 2026 Amazon.com and Affiliates. -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# 两项改进真机实测摘要 · 2026-08-12b

> 环境：VPC-local，**g6.xlarge（NVIDIA L4 24G，us-west-2）**，torch 2.13.0+cu130 / transformers 5.15.0 / sentence-transformers 5.7.0 / vLLM 官方 Docker `vllm/vllm-openai:latest`（30.8GB 镜像）。详见 `env.txt`。
> **所有数字取自机器输出，无手写。** 上一轮（A10G）数据在同级 `../results-20260812/`。

本轮针对上轮两个短板做针对性改进：
- **改进 A**：VPC 小模型延迟太高（上轮 Qwen2.5-7B transformers 直推 p50≈1.42s，vLLM 未起稳）→ 换 **Qwen3-4B-Instruct-2507（纯文本官方 dense、非思考）+ vLLM 官方 Docker**，求更低延迟。
- **改进 B**：代码专用嵌入缺席（上轮 jina-code 因 custom_code 兼容失败）+ 数据集不可靠（BigCloneBench 93% 误标）→ 换 **codefuse-ai/F2LLM-v2-4B（代码专用、Apache-2.0、原生 Qwen3Model）+ POJ-104（CodeXGLUE，Type-4 语义克隆）**。

---

## 1. 改进 A：Qwen3-4B-2507 + vLLM serving 延迟（suite6 语料，`vllm:` 后端哨兵确认真命中）

| 口径 | 类别命中 | 单发延迟 p50 | 生成 token 中位 | 原始文件 |
|---|---|---|---|---|
| transformers 直推（对照，无 serving 优化） | 2/4 | 2852.6ms | ~120 | `hf_qwen3_4b.json` |
| vLLM serving，完整契约（带 `reason`，max_tokens=128） | **4/4** | 2222.2ms | 100+ | `vllm_qwen3_4b.json` |
| vLLM serving，完整契约 + CUDA graph | **4/4** | 2182.3ms | 100+ | `vllm_qwen3_4b_cudagraph.json` |
| **vLLM serving，精简输出（去 `reason` 字段）** | **4/4** | **695.1ms** | **20** | `vllm_qwen3_4b_slim.json` |

**结论**：
- **两个反直觉发现**：① transformers 直推在 4B-2507 上反而只有 2/4、且比 vLLM 更慢（2852ms）——直推无 serving 优化、采样/停止判定不如 vLLM 稳。② 从 2222ms 压到 695ms 的关键**不是换后端、不是 CUDA graph**（2222→2182 几乎无差），**而是砍生成 token 数**：完整契约要模型吐一段中文 `reason`（100+ token），精简契约只留 `{sensitive,category,confidence}`（中位 20 token），单发延迟直接降到 1/3。
- **延迟主导因子是输出 token 数，不是模型/后端**——可直接迁移到生产的调参结论。
- **对同步腿的意义**：695ms 仍是「秒级半」量级，仍不该进同步阻断腿（对比 L0–L3.5 同步腿 p50≈14ms、RAG 16–45ms 差 1–2 个数量级），但对**异步告警**已足够。L4 该走异步的结论不变，且现在有 serving 口径真数字。
- **gp3 冷卷坑（工程记录）**：vLLM「卡在 Loading safetensors 0/3」并非 torch.compile/CUDA graph/显存问题，而是 gp3 冷卷 mmap 随机 4K 页错误瓶颈（~4.5MB/s）。用 `dd bs=8M` 顺序预读把权重灌进 page cache（147MB/s）后，vLLM 7.98s 载完。此为 serving 起稳前提。

## 2. 改进 B：代码专用嵌入 vs 通用嵌入 × 两领域数据集（阈值扫描，sklearn，PR 优先）

| 嵌入模型 | 参数 | 自建中文机密集 AP | POJ-104 代码克隆集 AP | 单发 embedding p50 | 原始文件 |
|---|---|---|---|---|---|
| **BAAI/bge-m3**（通用多语言） | 560M | **0.9302** (ROC 0.9015) | 0.7476 (ROC 0.6042) | **15.9ms** | `sweep_bge-m3_{selfbuilt,poj104}.json` |
| **codefuse F2LLM-v2-4B**（代码专用） | 4B | 0.8971 (ROC 0.8864) | **1.0000** (ROC 1.0000) | 44.9ms | `sweep_f2llm_{selfbuilt,poj104}.json` |

**结论**：
- **「没有万能嵌入」被实测坐实**：中文自然语言机密场景，通用 bge-m3 略胜（0.930 vs 0.897）；代码语义克隆场景，代码嵌入 F2LLM **碾压**（AP 1.000 完美分离 vs 0.748）。POJ-104 上 bge-m3 把异题负例打到 0.72–0.85、与同题正例 0.72–0.93 严重重叠，通用嵌入区分不了代码语义等价；F2LLM 负例 0.095–0.39、正例 0.52–0.91，阈值 0.52 完美分离。
- **选型顺序**：先按「拦自然语言机密还是源代码」定嵌入模型，再看单发延迟能否进同步腿——两个模型（15.9ms / 44.9ms）本轮都进得了同步腿预算。
- **数据集可靠性**：POJ-104（同题=Type-4 语义克隆正例，异题=负例）取代 BigCloneBench。BigCloneBench 经调研弃用——arXiv:2505.04311 实测其 WT3/T4 有 93% 误标、真值对里「Copy File」占 54%，污染已传播到 CodeXGLUE 衍生集。派生小评测集见同目录 `poj104_{corpus,eval}.jsonl`（10 题建库 / 30 正例 + 20 负例，运行时从 HF 下载后确定性派生）。

## 3. 口径与边界（诚实纪律）

- **A10G（上轮）vs L4（本轮）不同卡**：延迟数字不跨轮直接比，各自标口径。
- **serving vs 直推**：vLLM serving 数字与 transformers 直推数字口径不同，表内已分行。
- **英文 C/C++（POJ-104）vs 中文业务机密（自建集）域差大**：分层报告、绝不平均——域差本身是结论（§6.4 风险3）。
- **F2LLM 是通用多语言嵌入**（codefuse 代码团队出品、对代码友好），非 code-only；在代码集上的碾压是实测结果，不是先验假设。
- **仍待测**：14B 模型（L4 需量化）、vLLM serving 并发拐点（本轮只单发分位）、更大规模语料/评测集、跨语言（非 C/C++）代码克隆、含 L3.7 的整机 k6 分位。
