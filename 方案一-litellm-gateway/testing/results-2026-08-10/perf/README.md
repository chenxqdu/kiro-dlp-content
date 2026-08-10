<!-- Copyright (c) 2026 Amazon.com and Affiliates. -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 阶段6 性能测试原始输出归档(方案一网关,03 §9)

- 实例 `<TEST_INSTANCE_ID>`,m7i.2xlarge,us-west-2,8 vCPU / 32 GiB,单机合并部署(litellm + dlp-engine + presidio)
- 日期 2026-08-10;压测器 k6 v2.1.0(open-loop `constant-arrival-rate`)
- 上游用假 echo 端点 `fake_upstream.py`(§9.3 法1),把上游生成延迟从测量剔除,只留【网关 + DLP 引擎】净开销;REDACT 路径走完整改写+转发,客户端从 echo 回显里校验脱敏是否真生效(§9.6 源1)
- 所有敏感值均为公开示例/合成串(如 AWS 文档 key、Luhn 合成卡号),非真实凭证;内容不出实例(假上游绑 0.0.0.0 但端口 18080 不在实例 SG 任何 ingress 规则里)

## 文件清单

| 文件 | 内容 |
|---|---|
| `k6_B_r{30,60,70,80,90,100,150}.txt` | 实验 B 吞吐阶梯,每档 40s,找 95% 最大可检吞吐(拐点) |
| `k6_A.txt` / `summary_A.json` | 实验 A 纯攻击(local@20 + l3@20 = 40/s,40s),检出上限 + BLOCK/REDACT 路径延迟分位 |
| `k6_C.txt` / `summary_C.json` | 实验 C 混合主实验(合法背景 70/s + 攻击注入 5/s,60s),负载下拦截率 + 双源对账 |
| `k6_D.txt` / `summary_D.json` | 实验 D fail-closed 验证(长文本 2000tok 背景 15/s 压 Presidio 过载 + local5/s + l3only5/s,60s) |
| `stats_*.txt` | 各实验中段 `docker stats` 三容器 CPU/内存快照(§9.5) |

## 关键结论(数字见 03 §9.9~§9.13)

1. **吞吐拐点 ≈ 80 req/s**(短合法流,单副本 Presidio):≤80 零丢弃、迭代 p99<200ms;90 起 `dropped_iterations`>0、尾延迟入秒级。
2. **拦截正确性**:实验 A/C 全程 BLOCK 100%、REDACT 100% 脱敏生效、误杀率 0%、明文泄漏 0;双数据源(k6 check ⊕ 网关 metrics)逐类计数完全对齐。
3. **fail-closed 兜底(核心增量)**:Presidio 宕机时,默认 `block` 组 → 400 `forced_block=l3_unavailable`、卡号不出网关(泄漏=0);`keep` 对照组(复现旧 fail-open,**非生产**)→ 200 pass、同一张卡号明文到达上游 echo。**同一请求、同一故障,处置相反** —— 直接量化本轮改造的收益。
4. **过载下的诚实边界**:实验 D 把 Presidio 压到 750% CPU 时,超额请求在网关内**排队超时(status 0 客户端超时,内容未外发)**而非静默放行 —— 可用性下降、安全性不降,明文泄漏仍为 0。此时降级模式是"排队阻塞"而非"逐请求 L3 预算跳过",故 marker→强制拦截未触发;marker 通道已在停 Presidio 专项(§8.2.1)与本节 keep 对照中单独坐实。
