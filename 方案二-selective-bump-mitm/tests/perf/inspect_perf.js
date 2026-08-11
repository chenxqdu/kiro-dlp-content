// k6 性能测试脚本(方案二 /inspect 薄服务)——负载下拦截正确性 + 基准延迟分位。
//
// Copyright (c) 2026 Amazon.com and Affiliates.
// SPDX-License-Identifier: Apache-2.0
//
// 移植自方案一 testing/perf/dlp_perf.js(open-loop constant-arrival-rate,避免
// coordinated omission)。与方案一的两处本质差异(决定断言口径):
//
//   1) 目标是 /inspect 纯裁决薄服务:【不转发上游、不接 LLM】,恒返回 HTTP 200 +
//      verdict JSON(错误路径才 503/413/400)。故拦截判据看【返回 JSON 的 verdict】,
//      不是方案一的 HTTP 400。测的是【引擎裁决延迟本身】,不含网关+假上游成本。
//
//   2) 泄漏语义按【真实 MITM 数据流】判定(addon 依 verdict 决定写什么给上游):
//        verdict==BLOCK  → addon 短路,不发上游         → 绝不泄漏(正确)
//        verdict==REDACT → addon 把 redacted_body 写回上游 → 泄漏 iff 脱敏体仍含明文探针
//        verdict==PASS   → addon 转发【原始明文】上游    → 攻击向量被 PASS = 泄漏
//      唯一失败态 = 攻击向量的原始敏感明文会流向上游。本脚本专抓这两种泄漏。
//
// 用 __ENV.EXP 选实验:A(纯攻击定检出上限)/ B(纯合法找拐点)/ C(混合主实验)/
//                     D(停 Presidio 的 fail-closed 暴露)。
// 其余可调:RATE、DURATION、BG_RATE、ATK_RATE、DLP_URL、LONGTOK、PRE_VU。
//
// fail-closed(server.py:_forced_block_reason):L3 不可达/脱敏未生效时 /inspect
// 把 verdict 强制升级为 BLOCK 并带 forced_block 原因。实验 D 量化这一点:停 Presidio
// 后 L3-only 向量的处置分布(REDACT脱敏 / BLOCK强制拦截),泄漏率必须为 0。

import http from 'k6/http';
import { check } from 'k6';
import { Counter, Trend, Rate } from 'k6/metrics';
import { textSummary } from 'https://jslib.k6.io/k6-summary/0.1.0/index.js';

const V = JSON.parse(open('./vectors.json'));
const DLP_URL = (__ENV.DLP_URL || 'http://172.31.27.174:9000').replace(/\/$/, '');
const EXP = (__ENV.EXP || 'A').toUpperCase();
const LONGTOK = parseInt(__ENV.LONGTOK || '2000', 10);

// ---- 自定义指标:按处置路径分开的延迟 + 拦截率/泄漏率 ----
const dBlock = new Trend('inspect_block_ms', true);    // BLOCK 路径(裁决短路)
const dRedact = new Trend('inspect_redact_ms', true);  // REDACT 路径(脱敏)
const dPass = new Trend('inspect_pass_ms', true);      // PASS 路径(合法放行 / 攻击被放行)
const dOther = new Trend('inspect_other_ms', true);    // 非200(503背压/413/400)
const cLocalHandled = new Rate('atk_local_handled');   // 本地层类正确处置率(应=1)
const cL3Handled = new Rate('atk_l3_handled');         // L3-only 类正确处置率(过载/停Presidio下可能<1)
const cLeak = new Counter('plaintext_leak');           // ★明文将流向上游的泄漏计数(必须=0)
const cFalsePos = new Rate('legal_false_positive');    // 合法流误杀率(应=0)
const cForcedBlock = new Counter('forced_block');      // fail-closed 强制拦截计数
const cContractLeak = new Counter('contract_leak');    // ★响应体出现 matched/span 的契约破坏(必须=0)

// ---- 长合法文本(实验 D 背景:压 Presidio NER 超预算)----
function makeLong(nTok) {
  const unit = '这是一段用于压力测试的中文长文本,内容完全合法、不含任何敏感信息,目的是让 Presidio NER 引擎在长输入上消耗足够算力。';
  let s = '';
  while (s.length < nTok * 2) s += unit;  // 中文 ~2 char/token 粗估
  return s;
}
const LONG_TEXT = makeLong(LONGTOK);

const HEADERS = { headers: { 'Content-Type': 'application/json' } };

// CodeWhisperer 信封:与 tests/tier_a_smoke.sh、addon 注入点一致。
function body(text) {
  return JSON.stringify({
    conversationState: { currentMessage: { userInputMessage: { content: text } } },
  });
}
function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

// 契约铁证:响应体绝不含 matched/span(server._safe_rules 已剥离;此处做回归哨兵)。
function guardContract(res, id) {
  if (res.body && (res.body.indexOf('"matched"') >= 0 || res.body.indexOf('"span"') >= 0)) {
    cContractLeak.add(1);
    check(res, { [`${id} 契约泄漏(matched/span)!`]: () => false });
  }
}

// ---- 攻击请求:按 verdict JSON 断言(BLOCK / REDACT / PASS 三分支)----
function sendAttack(vec, cls) {
  const res = http.post(`${DLP_URL}/inspect`, body(vec.text), HEADERS);
  const rate = cls === 'local' ? cLocalHandled : cL3Handled;
  guardContract(res, vec.id);

  let j = null;
  try { j = JSON.parse(res.body); } catch (e) { j = null; }

  // 非200(503背压/413/400)或无 verdict:addon 对此 fail-closed(不转发),非泄漏但记背压。
  if (res.status !== 200 || !j || !j.verdict) {
    dOther.add(res.timings.duration);
    rate.add(false);
    check(res, { [`${vec.id} 非200(${res.status})`]: () => false });
    return;
  }

  if (j.verdict === 'BLOCK') {
    if (j.forced_block) cForcedBlock.add(1);
    dBlock.add(res.timings.duration);
    rate.add(true);
    check(res, { [`${vec.id} ${vec.expect}→BLOCK`]: () => true });
    return;
  }

  if (j.verdict === 'REDACT') {
    // addon 会把 redacted_body 写回上游 → 泄漏当且仅当脱敏体里仍有明文探针。
    const leaked = vec.plaintext_leak_probe && j.redacted_body &&
                   j.redacted_body.indexOf(vec.plaintext_leak_probe) >= 0;
    dRedact.add(res.timings.duration);
    if (leaked) {
      cLeak.add(1);
      rate.add(false);
      check(res, { [`${vec.id} 脱敏未生效·明文将转发!`]: () => false });
    } else {
      rate.add(true);
      check(res, { [`${vec.id} REDACT脱敏生效`]: () => true });
    }
    return;
  }

  // verdict === 'PASS':攻击向量被放行 → addon 转发【原始明文】上游 → 泄漏。
  cLeak.add(1);
  dPass.add(res.timings.duration);
  rate.add(false);
  check(res, { [`${vec.id} 攻击被PASS(原文将转发)!`]: () => false });
}

function sendLegal(vec, text) {
  const res = http.post(`${DLP_URL}/inspect`, body(text || vec.text), HEADERS);
  guardContract(res, vec.id);
  let j = null;
  try { j = JSON.parse(res.body); } catch (e) { j = null; }
  const verdict = j ? j.verdict : null;
  const falsePos = res.status === 200 && verdict === 'BLOCK';
  cFalsePos.add(falsePos);
  (res.status === 200 ? dPass : dOther).add(res.timings.duration);
  check(res, { [`${vec.id} 合法→非BLOCK`]: () => res.status === 200 && verdict !== 'BLOCK' });
}

// ---- exec 函数 ----
export function attackLocal() {
  const pool = [...V.attack_local_block, ...V.attack_local_redact];
  sendAttack(pick(pool), 'local');
}
export function attackL3() { sendAttack(pick(V.attack_l3only), 'l3only'); }
export function attackMixed() {
  const pool = [...V.attack_local_block, ...V.attack_local_redact, ...V.attack_l3only];
  const v = pick(pool);
  sendAttack(v, V.attack_l3only.indexOf(v) >= 0 ? 'l3only' : 'local');
}
export function legal() { sendLegal(pick(V.legal_short)); }
export function legalLong() { sendLegal({ id: 'LONG-LEGAL' }, LONG_TEXT); }

// ---- scenarios by EXP ----
const RATE = parseInt(__ENV.RATE || '20', 10);
const DUR = __ENV.DURATION || '60s';
const BG_RATE = parseInt(__ENV.BG_RATE || '20', 10);
const ATK_RATE = parseInt(__ENV.ATK_RATE || '5', 10);
const PRE_VU = parseInt(__ENV.PRE_VU || '100', 10);

function car(exec, rate, dur, preVU) {
  return { executor: 'constant-arrival-rate', rate, timeUnit: '1s', duration: dur,
           preAllocatedVUs: preVU, maxVUs: preVU * 4, exec };
}

const SCEN = {
  A: { attack_local: car('attackLocal', RATE, DUR, PRE_VU),
       attack_l3: car('attackL3', RATE, DUR, PRE_VU) },
  B: { background_legal: car('legal', RATE, DUR, PRE_VU) },
  C: { background_legal: car('legal', BG_RATE, DUR, PRE_VU),
       injected_attacks: car('attackMixed', ATK_RATE, DUR, Math.ceil(PRE_VU / 2)) },
  D: { background_long: car('legalLong', BG_RATE, DUR, PRE_VU),
       inject_local: car('attackLocal', ATK_RATE, DUR, 50),
       inject_l3: car('attackL3', ATK_RATE, DUR, 50) },
};

export const options = {
  scenarios: SCEN[EXP] || SCEN.A,
  summaryTrendStats: ['avg', 'min', 'med', 'p(95)', 'p(99)', 'p(99.9)', 'max'],
};

export function handleSummary(data) {
  const tag = `EXP=${EXP} RATE=${RATE} BG=${BG_RATE} ATK=${ATK_RATE} DUR=${DUR} URL=${DLP_URL}`;
  return {
    stdout: `\n===== 方案二 /inspect 性能测试 [${tag}] =====\n` +
            textSummary(data, { indent: '  ', enableColors: false }),
    [`summary_${EXP}.json`]: JSON.stringify(data, null, 2),
  };
}
