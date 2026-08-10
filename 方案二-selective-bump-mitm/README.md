# 方案二 · 选择性 bump MITM + VPC 内 DLP 联动

> Kiro（AWS Kiro / Amazon Q AI IDE）推理流量**内容审查**方案。把一台 SNI 透传代理升级为
> **选择性中间人**：`ssl_preread` 读明文 SNI 做四层路由，**仅** `runtime.us-east-1.kiro.dev`
> 一条被解密送 VPC 内 DLP 引擎裁决（`PASS / REDACT / BLOCK`），**其余 SNI 一律 L4 透传永不解密**。
>
> 2026-07-30 已在专用**验证节点**部署，各层测试**全绿**（Tier D 逐层探针 2026-08-05 补齐）。本目录自成一体，与方案一
> （[`方案一-litellm-gateway/`](../方案一-litellm-gateway/)，opt-in LiteLLM 网关）在仓库里**平级并列**，
> 共用根部的 [`engine/`](../engine/) 引擎。整体思路见 [00 总览](../00-总览/)：
> [01 宣传](../00-总览/01-方案介绍-宣传.md) / [02 技术博客](../00-总览/02-技术博客.md)。

---

## 📚 文档导航（按此顺序读）

| # | 文档 | 读它来了解 |
|---|---|---|
| 1 | [**方案二-01-设计与架构.md**](方案二-01-设计与架构.md) | 为什么「选择性」bump、认证模型决定哪条腿可改包、拓扑、组件职责、CA 三级信任 + 两个证书坑、fail 语义、9 条安全红线、与方案一对比 |
| 2 | [**方案二-02-部署指南.md**](方案二-02-部署指南.md) | 前置条件、`config.env` 变量、单命令部署、八步编排详解、CA 分发（各 TLS 栈）、状态与回滚/拆除 |
| 3 | [**方案二-03-测试报告.md**](方案二-03-测试报告.md) | 四层**实测全绿**结果 + wire-byte 铁证 + Tier C 交叉核对 + fail 四子测 + 两坑复盘 + DoD |
| 4 | [**方案二-04-真机踩坑实录.md**](方案二-04-真机踩坑实录.md) | **真实 Kiro 桌面端端到端**:合成全绿后真机连翻三轮的六个坑（工具目录 L2 误报 / 历史重扫 / 协议字段 NER 误判 / 脱敏跨字段污染…）+ 修复清单 F0–F6 + 残留与教训 |
| — | [TEST-PLAN.md](TEST-PLAN.md) | 测试**计划**（oracle/期望值，`应该怎样`）——与 03（`实际怎样`）配套 |

> 心智模型：**01 = 为什么这样设计**，**02 = 怎么部署**，**03 = 实测证明它对**，**04 = 真机把假设打碎再修对**，**TEST-PLAN = 判据来源**。

---

## 🗂️ 代码与产物

| 文件/目录 | 作用 |
|---|---|
| [`config.env.example`](config.env.example) | 全部部署变量的模板（区域解耦 D5、网络复用、DLP 联动、选择性 bump、CA 参数）。`cp config.env.example config.env` 后填入自己的资源 ID；`config.env` 已 git-ignored |
| [`deploy.sh`](deploy.sh) | 幂等编排器（8 步：预检→网络→SG→SG联动→PrivateLink→IAM→user-data→EC2/EIP→输出） |
| [`gen-ca.sh`](gen-ca.sh) | 三级 CA 生成器（EC2 现场跑，私钥不出机）；已固化两个证书坑的修法 |
| [`kiro_addon.py`](kiro_addon.py) | mitmproxy 联动 addon（`KiroDLP`：gate→调 DLP→PASS/REDACT/BLOCK 三态 + fail 分流 + 反自环） |
| [`cleanup.sh`](cleanup.sh) | 逆序拆除（先撤 SG 联动规则再删 proxy SG；仅删本次创建资源，复用网络保留） |
| `http_service/` + [`docker-compose.dlp-http.yml`](docker-compose.dlp-http.yml) | DLP 判定薄服务（`dlp_http.server`，复用 `kiro-dlp-engine` 镜像） |
| [`tests/`](tests/) | 各层测试脚本（Tier A/B/C/**D**/fail）+ [`run_all.sh`](tests/run_all.sh) 一键运行器 |
| [`results-2026-08-05/`](results-2026-08-05/) | Tier D 逐层探针经真实链路的**原始 stdout**（逐字节未加工） |
| `.deploy-state.env` | 本次资源清单（git-ignored，供 cleanup 逆序拆除） |
| `client-hosts.txt` | 客户端 hosts 映射（各 Kiro 域→proxy EIP；**EC2 本机绝不改 hosts** 否则自环） |

---

## 🚀 快速上手

### 部署（本机，`default` profile / us-west-2）
```bash
cd /Users/chenxqdu/cowork/kiro-dlp-content/方案二-selective-bump-mitm && ./deploy.sh
```
细节见 [方案二-02-部署指南.md](方案二-02-部署指南.md)。

### 一键测试（在验证节点 proxy 本机，经 SSM）
> 测试脚本不随 user-data 上 EC2（受 25600 字节限制，只内嵌了 gen-ca.sh + kiro_addon.py）。
> 先把本目录 `tests/` 经 SSM 推到验证节点家目录（例：`~/tests/`），再运行：
```bash
cd ~/tests && ./run_all.sh                       # 跑全部层：0 a b c d f
```
```bash
./run_all.sh --list        # 列出各层
```
```bash
./run_all.sh 0 a           # 只跑预检 + Tier A
```
`run_all.sh` 逐层判定 PASS/FAIL 并汇总，日志落 `/tmp/kiro-mitm-tests/`。各层含义：

| 层 | 脚本 | 验证 |
|---|---|---|
| `0` | （内联） | §2 bump 域严格校验（Verify 0 + issuer=我方中间 CA）+ §3 透传域红线（issuer=Amazon） |
| `a` | [`tier_a_smoke.sh`](tests/tier_a_smoke.sh) | §4 Tier A：直连 DLP `/inspect` 三态裁决 + 脱敏字段不外泄 |
| `b` | [`tier_b_wire.sh`](tests/tier_b_wire.sh) | §4 Tier B：wire-byte 铁证（发往上游的字节：PASS 逐字节一致 / REDACT PII 消失 / BLOCK 上游零命中） |
| `c` | [`tier_c_real_upstream.sh`](tests/tier_c_real_upstream.sh) | §4 Tier C：真实上游交叉核对（PASS 到 AWS / BLOCK 我方短路，来源域可区分） |
| `d` | [`tier_d_relayer_layers.sh`](tests/tier_d_relayer_layers.sh) | §4.4 Tier D：把 Tier B 那条真实链路**按引擎层拆开**，L0/L1/L2/L3/L3.5 各层探针，双断言 verdict + `top_layer`（8/8，[原始输出](results-2026-08-05/tier_d_relayer_layers.txt)） |
| `f` | [`tier_fail_modes.sh`](tests/tier_fail_modes.sh) | §5 fail 模式四子测（不可达吃策略 / HTTP503 恒 closed，D3/D4） |

> Tier B/C/D/fail 脚本各自起**临时** mitmdump（9443）或走**生产** 443，绝不干扰彼此；全程只打 127.0.0.1。
>
> **Tier D ≠ 方案一 stage5 的 78 条**：stage5（[`engine/tests/run_layers.py`](../engine/tests/run_layers.py)）是
> `import dlp` **直调各层 `scan()`** 的单测——不经引擎聚合、不经任何代理，证明「规则本身对」；
> Tier D 每条探针都**穿过真实 addon → HTTP → `:9000`** 再由 echo 上游做字节取证，证明「规则在真链路上仍然对」。
> 两者互补，**stage5 全绿不替 Tier D 背书**（addon 的字段定位/改包/短路全在 stage5 覆盖之外）。详见 [03 §4.4](方案二-03-测试报告.md)。

#### 逐条三合一：`inspect_cases --via-http`（输入 + 效果 + 逐条延迟）

`run_all.sh` 的 Tier A/D 有「效果」无「逐条延迟数字」。要把**每条用例的输入原文 + 裁决/脱敏 + 分层延迟**
拼在一张卡片里，用共享引擎的只读检视器打本服务的 `/inspect`（返回 JSON 自带 `latency_ms` + `http_total`）：

```bash
# 在能访问 :9000 的节点（DLP 主机 / 经 SSM），engine/ 目录内
python3 -m tests.inspect_cases --set offline \
  --via-http http://172.31.27.174:9000 \
  --format md --report results-manual/via_http_YYYYMMDD
```

先 `GET /health` 探活，不可达即整批 SKIP（不伪造）；REDACT 显示 `redacted_body`，fail-closed 时高亮 `forced_block`。
完整用法、卡片字段、延迟口径（单发 ≠ k6 分位）见
[00-总览/03-手动复现指南-逐条三合一.md](../00-总览/03-手动复现指南-逐条三合一.md) §4。

### 一键回滚（不拆机器，退化为透传）
```bash
# config.env 里 MITM_BUMP_DOMAIN="" 后重部署 → 全透传，不解密任何流量
```

### 彻底拆除
```bash
cd /Users/chenxqdu/cowork/kiro-dlp-content/方案二-selective-bump-mitm && ./cleanup.sh
```

---

## ⚠️ 安全红线（详见 [01 §6](方案二-01-设计与架构.md)）

1. **CA 私钥不出机**：`root.key`/`inter.key`/`mitmproxy-ca.pem` 仅在 EC2 `/etc/mitm/certs` 600，永不进 git、永不外传；客户端只装 `root-ca-for-clients.crt`。
2. **NC 只 permitted DNS=kiro.dev**：绝不加 excluded IP（否则叶子 IP-SAN 触发 code 48）；这套 CA 物理上只能伪造 kiro.dev 子域。
3. **mitm 只绑 `127.0.0.1:8443`**：绝不 0.0.0.0；外部只能经 nginx。
4. **透传腿绝不解密**：透传域 issuer 若出现我方 CA = 误 bump，立即停止回滚。
5. **绝不 `NODE_TLS_REJECT_UNAUTHORIZED=0` / `rejectUnauthorized:false`**：pinning 判定失败就回滚，绝不禁校验绕过。
6. **同步腿绝不触 L4**：`top_layer=L4` 是红线告警；L4 语义永远异步，且只用 VPC 内 LLM，绝不第三方 LLM。
7. **绝不碰生产 SNI 透传节点**（us-east-1，实例 ID / EIP 见内部部署记录）：方案二是独立验证节点。

---

## 📌 当前状态

- ✅ 已部署验证节点 `<VERIFY_INSTANCE_ID>`（c6g.large arm64, us-west-2, EIP <VERIFY_NODE_EIP>）
- ✅ 各层测试全绿（§2 bump / §3 透传红线 / §4 Tier A·B·C / §5 fail 四子测）
- ✅ **Tier D 逐层探针经真实代理链路**重验 L0–L3.5（2026-08-05 补测，`verdict` + `top_layer` 双断言 **8/8**，
  收尾复核生产 `kiro-mitm` 未受影响）——见 [03 §4.4](方案二-03-测试报告.md) 与 [原始 stdout](results-2026-08-05/tier_d_relayer_layers.txt)
- ✅ **真实 Kiro 桌面端端到端三态全绿**（2026-08-03：装 root CA + hosts override + SG 白名单；PASS 正常回答 / REDACT 手机号链路遮蔽 / BLOCK 真密钥 `CorpDLPBlockedException`）——过程中修复六个真机坑，见 [方案二-04-真机踩坑实录.md](方案二-04-真机踩坑实录.md)
- ⏸ 遗留：REDACT 邮箱规则覆盖（引擎规则问题非联动 bug）、presidio 中文 NER 噪声调优、04 §9 残留清单
