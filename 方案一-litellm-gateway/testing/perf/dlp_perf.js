// k6 性能测试脚本(方案一网关,03 文档 §9)——拦截成功率 + 压测下拦截延迟。
//
// Copyright (c) 2026 Amazon.com and Affiliates.
// SPDX-License-Identifier: Apache-2.0
//
// open-loop(constant-arrival-rate)避免 coordinated omission(§9.2)。
// 用 __ENV.EXP 选实验:A(纯攻击定上限)/ B(纯合法定基线)/ C(混合主实验)/ D(fail-closed 暴露)。
// 其余可调:RATE、DURATION、BG_RATE(C/D 背景流速)、ATK_RATE(C/D 攻击注入速)、
//           BASE_URL、MODEL、KEY、LONGTOK(长文本目标 token 数)。
//
// 拦截判据(§9.6 源1,客户端侧权威):
//   BLOCK  向量 → HTTP 400 且 body.detail.error == "blocked_by_corp_dlp"(或 forced_block)
//   REDACT 向量 → 要么 200 且【响应 echo 里原始 PII 明文已消失】(脱敏生效)
//                 要么 400 forced_block(fail-closed:L3 降级时强制拦截)——两者都算"正确处置"
//                 ★ 唯一失败态 = 200 且明文 PII 仍在(fail-open 泄漏)——本脚本专门抓它
//   合法   向量 → 200 且未被误 BLOCK(误杀率)
//
// 网关现为 fail-closed(dlp_guardrail 读 notes 强制升级):故 L3-only 向量在 Presidio
// 过载时的正确行为是"被强制 BLOCK",而非旧 fail-open 版的"静默 PASS 泄漏"。实验 D
// 正是量化这一点:过载下 L3-only 的处置分布(200脱敏 / 400强制拦截),泄漏率必须为 0。

import http from 'k6/http';
import { check } from 'k6';
import { Counter, Trend, Rate } from 'k6/metrics';
import { textSummary } from 'https://jslib.k6.io/k6-summary/0.1.0/index.js';

const V = JSON.parse(open('./vectors.json'));
const BASE_URL = __ENV.BASE_URL || 'http://localhost:4000';
const MODEL = __ENV.MODEL || 'echo-fast';
const KEY = __ENV.KEY || '';
const EXP = (__ENV.EXP || 'A').toUpperCase();
const LONGTOK = parseInt(__ENV.LONGTOK || '2000', 10);

// ---- 自定义指标:按处置路径分开的延迟 + 拦截率/泄漏率 ----
const dBlock = new Trend('dlp_block_ms', true);     // BLOCK 路径(400 短路,不打上游)
const dRedact = new Trend('dlp_redact_ms', true);   // REDACT 路径(改写+转发)
const dPass = new Trend('dlp_pass_ms', true);       // PASS 路径(纯放行)
const cLocalHandled = new Rate('atk_local_handled');   // 本地层类正确处置率(应=1)
const cL3Handled = new Rate('atk_l3_handled');         // L3-only 类正确处置率(过载下可能<1)
const cLeak = new Counter('plaintext_leak');           // ★明文 PII 泄漏计数(必须=0)
const cFalsePos = new Rate('legal_false_positive');    // 合法流误杀率(应=0)
const cForcedBlock = new Counter('forced_block');      // fail-closed 强制拦截计数

// ---- 长合法文本(实验 D 背景:压 Presidio 超预算)----
function makeLong(nTok) {
  const unit = '这是一段用于压力测试的中文长文本,内容完全合法、不含任何敏感信息,目的是让 Presidio NER 引擎在长输入上消耗足够算力。';
  let s = '';
  while (s.length < nTok * 2) s += unit;  // 中文 ~2 char/token 粗估
  return s;
}
const LONG_TEXT = makeLong(LONGTOK);

function headers() {
  const h = { 'Content-Type': 'application/json' };
  if (KEY) h['Authorization'] = `Bearer ${KEY}`;
  return h;
}
function body(text) {
  return JSON.stringify({ model: MODEL, messages: [{ role: 'user', content: text }], max_tokens: 32 });
}
function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

// ---- 攻击请求:BLOCK / REDACT 分别断言 ----
function sendAttack(vec, cls) {
  const res = http.post(`${BASE_URL}/v1/chat/completions`, body(vec.text), { headers: headers() });
  const rate = cls === 'local' ? cLocalHandled : cL3Handled;

  if (vec.expect === 'block') {
    const ok = res.status === 400 && res.body.includes('blocked_by_corp_dlp');
    dBlock.add(res.timings.duration);
    rate.add(ok);
    check(res, { [`${vec.id} BLOCK→400`]: () => ok });
    return;
  }
  // expect == redact
  if (res.status === 400) {
    // fail-closed:L3 降级被强制拦截,也算"正确处置"(内容没泄)
    const forced = res.body.includes('forced_block') || res.body.includes('blocked_by_corp_dlp');
    if (res.body.includes('forced_block')) cForcedBlock.add(1);
    dBlock.add(res.timings.duration);
    rate.add(forced);
    check(res, { [`${vec.id} REDACT→400(fail-closed)`]: () => forced });
    return;
  }
  if (res.status === 200) {
    // 200 放行:必须确认原始 PII 明文已从(回显的)内容里消失
    const leaked = vec.plaintext_leak_probe && res.body.includes(vec.plaintext_leak_probe);
    dRedact.add(res.timings.duration);
    if (leaked) {
      cLeak.add(1);
      rate.add(false);
      check(res, { [`${vec.id} 明文泄漏!`]: () => false });
    } else {
      rate.add(true);
      check(res, { [`${vec.id} REDACT→200脱敏生效`]: () => true });
    }
    return;
  }
  rate.add(false);
  check(res, { [`${vec.id} 意外状态 ${res.status}`]: () => false });
}

function sendLegal(vec) {
  const res = http.post(`${BASE_URL}/v1/chat/completions`, body(vec.text), { headers: headers() });
  const falsePos = res.status === 400;  // 合法流被 400 = 误杀
  cFalsePos.add(falsePos);
  dPass.add(res.timings.duration);
  check(res, { [`${vec.id} 合法→200`]: () => res.status === 200 });
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
  sendAttack(v, V.attack_l3only.includes(v) ? 'l3only' : 'local');
}
export function legal() { sendLegal(pick(V.legal_short)); }
export function legalLong() {
  const res = http.post(`${BASE_URL}/v1/chat/completions`, body(LONG_TEXT), { headers: headers() });
  cFalsePos.add(res.status === 400);
  dPass.add(res.timings.duration);
  check(res, { 'long-legal→200': () => res.status === 200 });
}

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
  const tag = `EXP=${EXP} RATE=${RATE} BG=${BG_RATE} ATK=${ATK_RATE} DUR=${DUR}`;
  return {
    stdout: `\n===== DLP 性能测试 [${tag}] =====\n` + textSummary(data, { indent: '  ', enableColors: false }),
    [`summary_${EXP}.json`]: JSON.stringify(data, null, 2),
  };
}
