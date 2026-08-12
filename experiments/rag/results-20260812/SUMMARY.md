<!-- Copyright (c) 2026 Amazon.com and Affiliates. -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# RAG 相似度拦截（L3.7）真机实测摘要 · 2026-08-12

> 环境：VPC-local，**g5.xlarge（NVIDIA A10G 24G，us-west-2a）**，与 DLP 主机同 AZ、同 VPC 私网。
> embedding 自托管（sentence-transformers，GPU），numpy 精确余弦检索（无 ANN），机密向量不出 VPC。
> 语料库 5 条合成中文机密（风控加权/定价扩张/推荐排序/毛利公式/流失模型，不涉真密）；
> 评测集 23 条 = 12 改写正例（同义/改名/中英混排/结构重排）+ 6 邻近负例 + 5 阴性对照。
> 原始数据：`sweep_bge-m3.json` / `sweep_minilm.json` / `latency_bge-m3.txt`。**所有数字取自机器输出，无手写。**

## 1. 两个 VPC-local embedding 模型对照（阈值扫描，PR 优先）

| 模型 | 参数 | AP | ROC-AUC | recall=1.0 时 precision | 推荐阈值 |
|---|---|---|---|---|---|
| **BAAI/bge-m3** | 560M | **0.9302** | **0.9015** | **0.706** | 0.6485 |
| paraphrase-multilingual-MiniLM-L12-v2 | 118M | 0.8768 | 0.8485 | 0.667 | 0.3436 |

- **bge-m3 明显更优**（AP 0.93 vs 0.88），中英混排质量印证选型。
- **两者都印证「阈值是机制性误报旋钮」（博客 §6.4 风险1）**：要 recall=1.0（不漏任何机密），阈值必须压低，
  代价是 precision 掉到 0.67–0.71——邻近负例（用相同业务术语的合法内容）被误伤。这是真实、结构性的权衡，
  不是可调没调好。

## 2. 分层：改写强度 vs 相似度（bge-m3）

| 改写强度 | 正例相似度区间 | 判读 |
|---|---|---|
| synonym 同义改写 | 0.78–0.91 | 最好抓 |
| restructure 结构重排 | 0.77–0.85 | 好抓 |
| mixed 中英混排 | 0.68–0.78 | 可抓，区间下探 |
| rename 变量改名（代码化） | 0.65–0.77 | 最难，与负例区间重叠 |
| **near-negative 邻近负例** | **0.57–0.73** | **与 rename/mixed 正例重叠 → 误报来源** |
| control 阴性对照 | 0.41–0.50 | 干净分离，绝不误伤 |

**关键发现**：阴性对照（快排/闲聊等无关内容）与机密语料相似度稳定 <0.5，干净分离；
真正的难点是「用了相同业务术语但合法」的**邻近负例**与「改动较大的改写正例」在 0.6–0.73 区间交叠——
这正是语义 DLP 的固有难点，靠单一余弦阈值无法完美切分，需配合人工复核或更强模型/更细语料。

## 3. 可解释性（RAG 相对纯 LLM 的核心优势）

**12/12 改写正例的 top-1 命中都正确指向其源机密文档**（如 P-risk-* 全部命中 `risk-weighting`）。
即命中时能明确指出「与哪一份登记机密相似度多少」——可追溯、可审计、可撤回，纯 LLM 判断给不了。

## 4. 延迟（VPC-local）

| 项 | 实测 |
|---|---|
| bge-m3 单发（GPU 编码 + numpy 检索，warm） | p50=17.9ms / p95=18.3ms / p99=18.3ms（n=50） |

- **≈18ms，与 L0–L3.5 同步腿净成本（薄服务 p50≈14ms / 网关内 p50≈27.5ms）同量级** →
  **RAG 可进同步腿**（实测支撑博客 §6.5「若检索够快可进同步」的推测）。
- 语料 5 条，暴力余弦可忽略；主成本是 GPU 编码。语料涨到几千条余弦仍毫秒级。

## 5. 诚实边界（本轮实测的局限）

1. **语料库仅 5 条、评测集 23 条**——量级小，AP/precision 是**方向性**证据，不是生产规模统计；生产需扩语料 + 扩评测集重标定。
2. **jina-embeddings-v2-base-code（代码专用模型）未跑成**：其 custom modeling 代码依赖旧版 transformers API
   （`find_pruneable_heads_and_indices`），与本机 transformers 5.x 不兼容 → 报 ImportError。故「代码专用 vs 通用
   embedding」对比**本轮缺代码专用一侧**，改用多语言 MiniLM 作轻量对照。代码专用模型的收益仍**待测**（需固定
   兼容的 transformers 版本或换 TEI 镜像）。
3. **BigCloneBench 子集未叠加**：本轮聚焦中文机密自建集；英文代码克隆 benchmark 未跑，留待后续（域差本身是发现）。
4. **A10G 而非 g6/L4**：g6.xlarge 当时全 AZ 无容量，改用同级 g5.xlarge（A10G 24G）。延迟量级可参考，
   L4 上的确切数字略有差异。
5. **HF offline 部署经验**：首次联网检查会因 unauthenticated rate-limit 卡启动；生产 VPC-local 应 `HF_HUB_OFFLINE=1`
   预缓存模型（本轮实测坑，已记录）。
