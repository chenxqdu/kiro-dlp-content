"""DLP 分层引擎编排(SPEC §3 流水 + §2 聚合)。

铁律:
- 同步 verdict 只由 L0–L3.5 聚合;L4 只产 AsyncAlert,永不改 verdict。
- 先扫原文再扫每个变体;每条 hit 带 source 标明预处理来源。
- L3(Presidio)不可达 → notes 标注 "L3 缺席",绝不静默当 PASS。
- verdict==REDACT 时产出 redacted_text;dict 入参 redact 后仍是合法 JSON(MCP-06)。
"""
from __future__ import annotations

import copy
import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from . import (
    egress,
    extract,
    l0_regex,
    l1_secrets,
    l2_entropy,
    l3_presidio,
    l35_glossary,
    l4_semantic,
    normalize,
)
from .types import (
    AsyncAlert,
    Hit,
    InjectionPoint,
    Layer,
    ScanResult,
    Verdict,
    layer_rank,
)


@dataclass
class EngineConfig:
    presidio_languages: tuple[str, ...] = ("en", "zh")
    l3_timeout: float = 2.0
    run_l3_on_all_variants: bool = True   # False = 只扫 raw+normalized(省 HTTP)
    use_bedrock_l4: bool = False           # 离线单测走启发式;标定时置 True
    l4_model_key: str = "main"             # "main"=Qwen3-32B / "control"=Llama-3.1-8B
    redact_mask: str = "[REDACTED:{entity}]"
    # ---- L3 大 body 性能(套件:去重+省扫+并发,SPEC §5-L3 性能补丁)----
    # 现网(mitmproxy addon → /inspect)body 可达数百 KB(Kiro 每次推理都带系统提示 +
    # 工具 schema + 历史)。原实现逐 unit×逐变体×逐语言【串行】调 Presidio,请求数爆炸、
    # 耗时线性叠加至数十秒 → addon 超时 → fail-closed 全 503(DoS 级缺陷)。三管齐下:
    #   1) 全局跨-unit 去重:相同变体只扫一次(工具 schema description 大量重复,去重率~70%)。
    #   2) 省扫:l3_max_variant_len 之上的超长文本(系统提示/整文件)PII 检出价值极低,
    #      切块只取前若干块,避免单个 40KB 文本吃掉 50% 总时间。
    #   3) 并发:唯一变体扇入线程池并发调 Presidio(配合 analyzer WORKERS>1)。
    l3_concurrency: int = 16               # L3 并发线程数(0/1 = 退回串行,便于对照)
    l3_max_variant_len: int = 4096         # 超此长度的变体按块切,只扫前 l3_max_chunks 块
    l3_chunk_size: int = 1024              # 分块粒度(字符)
    l3_max_chunks: int = 4                 # 每个超长变体最多扫的块数(前 N 块)
    # ---- L3 时间预算兜底(真机验证发现:真实 Kiro body≈317KB 每段唯一、去重无效,
    # presidio 单 worker 串行时 L3 可达 ~24s ≫ addon DLP_TIMEOUT=8s → fail-closed 503
    # → Kiro 反复重试 → "Too many requests")。加硬时间预算:并发扫描累计超 l3_budget_s
    # 后,尚未完成的唯一变体一律标 partial(→ l3_state.incomplete → 上层 fail-closed 升 BLOCK),
    # 绝不静默当 PASS。保证同步腿 L3 墙钟永不超预算,守住 addon 8s 线。0 = 不设预算(旧行为)。
    l3_budget_s: float = 6.0


class DLPEngine:
    def __init__(self, config: EngineConfig | None = None):
        self.cfg = config or EngineConfig()

    # ---- 变体带标签展开(source 精确到预处理路径,满足 §4 铁律)----
    def _labeled_variants(
        self, text: str, session_window: list[str] | None
    ) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        seen: set[str] = set()

        def add(s: str | None, label: str) -> None:
            if s and s not in seen:
                seen.add(s)
                out.append((s, label))

        add(text, "raw")
        norm = normalize.normalize(text)
        add(norm, "normalized")
        add(normalize.strip_separators(norm), "stripped-sep")
        # §4 铁律:变体命中的 source 必须标明来源。decode_variants 现返回
        # (变体文本, 类型标签),类型 ∈ {base64,hex,rot13},逐条精确标注,不再靠位置猜。
        for v, kind in normalize.decode_variants(norm):
            add(v, f"decoded:{kind}")
        add(normalize.fold_concat(norm), "folded")

        if session_window:
            joined = "".join(session_window) + text
            jn = normalize.normalize(joined)
            add(jn, "session-window")
            add(normalize.strip_separators(jn), "session-window")

        return out

    # ---- 内容层扫描:一个文本单元 → 多变体 → L0/L1/L2/L3.5(同步);L3 候选另收集并发 ----
    def _scan_text_unit(
        self,
        text: str,
        field_path: str | None,
        session_window: list[str] | None,
        latency: dict[str, float],
        variants_sink: list[str],
        l3_pending: list[tuple[str, str, str | None]],
    ) -> list[Hit]:
        """同步跑 L0/L1/L2/L3.5(全是本地 CPU、亚毫秒),把该 unit 的 L3 待扫变体
        追加进 l3_pending(不在此发 HTTP)。L3 的实际调用由 scan() 全局去重后并发执行,
        避免逐 unit×逐变体串行 Presidio 造成的耗时爆炸。"""
        hits: list[Hit] = []
        variants = self._labeled_variants(text, session_window)

        for variant, src in variants:
            variants_sink.append(variant)

            t = time.perf_counter()
            for h in l0_regex.scan(variant, source=src):
                h.field_path = field_path
                hits.append(h)
            latency["L0"] = latency.get("L0", 0.0) + (time.perf_counter() - t) * 1000

            t = time.perf_counter()
            for h in l1_secrets.scan(variant, source=src):
                h.field_path = field_path
                hits.append(h)
            latency["L1"] = latency.get("L1", 0.0) + (time.perf_counter() - t) * 1000

            t = time.perf_counter()
            # L2 高熵检测只在「含义保真」变体上有效:raw/normalized/decoded。
            # stripped-sep/folded/session-window 会把英文散文重组成假高熵长串,
            # 真机 tools/history 的 L2 误报 BLOCK 全部由此而来(机制性误报,非个例)。
            # decoded 必须保留:还原 base64/hex/rot13 藏匿凭证正是熵检测的正当猎物。
            if src in ("raw", "normalized") or src.startswith("decoded:"):
                for h in l2_entropy.scan(variant, source=src):
                    h.field_path = field_path
                    hits.append(h)
            latency["L2"] = latency.get("L2", 0.0) + (time.perf_counter() - t) * 1000

            # L3 Presidio 昂贵(HTTP):此处只**登记**待扫变体,不发请求。
            # 省扫:run_l3_on_all_variants=False 时仅 raw/normalized 参与(编码混淆变体的
            # BLOCK 级凭证已由 L0/L1 捕获,L3 PII 扫它们价值极低)。
            run_l3 = self.cfg.run_l3_on_all_variants or src in ("raw", "normalized")
            if run_l3:
                l3_pending.append((variant, src, field_path))

            t = time.perf_counter()
            for h in l35_glossary.scan(variant, source=src):
                h.field_path = field_path
                hits.append(h)
            latency["L3.5"] = latency.get("L3.5", 0.0) + (time.perf_counter() - t) * 1000

        return self._drop_rot13_pseudo(hits)

    # ---- §4 收尾:剔除 rot13 变体"变造"出的伪 PII ----
    @staticmethod
    def _drop_rot13_pseudo(hits: list[Hit]) -> list[Hit]:
        # rot13 是全文对合变换(自身即逆):对良性明文(如 alice@example.com)整体 rot13
        # 会得到 nyvpr@rknzcyr.pbz 这类"看着像真值、实则原文不存在"的串,骗过 L0 保留域名
        # 白名单 / 诱使 Presidio 误报 PERSON —— 正是 §4 所指"解出乱码→丢弃,不产生噪声"。
        # rot13 的正当用途只有一个:还原攻击者用 rot13 藏起来的【凭证】(BLOCK 级,套件3
        # 编码规避),这类必须保留。故 rot13 变体只认 BLOCK 级命中,REDACT 级一律当噪声丢弃:
        #   · 保 FP-06(alice@example.com→PASS)、套件2 零误报;
        #   · 不回归:被 rot13 藏起来的真 AKIA/PEM 仍解得出并 BLOCK。
        # 判据用 h.source(已按预处理路径精确标注),不误伤 normalized/base64/hex 等
        # "含义保留"变体里的真实 PII(如 EVA-11 中文数字身份证走 normalized,不受影响)。
        return [
            h
            for h in hits
            if not (h.source == "decoded:rot13" and h.action is not Verdict.BLOCK)
        ]

    # ---- L3 全局并发扫描(去重 + 省扫 + 超长切块 + 线程池)----
    def _scan_l3_concurrent(
        self,
        l3_pending: list[tuple[str, str, str | None]],
        latency: dict[str, float],
        l3_state: dict,
    ) -> list[Hit]:
        """把所有 unit 收集到的 L3 待扫变体全局去重后并发调 Presidio。

        - 去重键 = variant 文本(相同文本无论出现在哪个 field 都只调一次 analyzer;
          命中回填时把 field_path 补上——PII 位置以首次登记的 field 为准,足够审计定位)。
        - 超长变体(> l3_max_variant_len)切块,只扫前 l3_max_chunks 块:系统提示 / 整文件
          这类超长文本 PII 检出价值低,却单个吃掉大半耗时(实测 44KB 单请求 823ms)。
        - 时间预算(l3_budget_s):并发累计墙钟超预算后,尚未完成的唯一变体一律标 partial
          (→ incomplete → 上层 fail-closed 升 BLOCK),保证同步腿 L3 永不超预算,守住
          addon 8s 线。绝不因超时静默当 PASS(D3 铁律)。
        - status 聚合沿用原语义:任一变体 unreachable→down+incomplete;partial→incomplete。
          并发下各请求独立,主线程汇总,无竞态。
        """
        if not l3_pending:
            return []

        # 全局去重(保序,首次登记的 src/field 代表该文本)
        seen: dict[str, tuple[str, str | None]] = {}
        for variant, src, fp in l3_pending:
            if variant not in seen:
                seen[variant] = (src, fp)
        uniq = list(seen.items())  # [(variant, (src, fp)), ...]

        def _work(item):
            variant, (src, fp) = item
            # 超长切块:只取前 max_chunks 块(避免单个巨型文本吃满 Presidio)
            if len(variant) > self.cfg.l3_max_variant_len:
                cs = self.cfg.l3_chunk_size
                chunks = [variant[i:i + cs] for i in range(0, len(variant), cs)]
                chunks = chunks[: self.cfg.l3_max_chunks]
            else:
                chunks = [variant]
            hits_local: list[Hit] = []
            worst = "ok"  # ok < partial < unreachable(取最坏)
            for ch in chunks:
                h_ch, status = l3_presidio.scan(
                    ch, source=src, languages=self.cfg.presidio_languages
                )
                for h in h_ch:
                    h.field_path = fp
                    hits_local.append(h)
                if status == "unreachable":
                    worst = "unreachable"
                elif status == "partial" and worst != "unreachable":
                    worst = "partial"
            return hits_local, worst

        t = time.perf_counter()
        workers = max(1, self.cfg.l3_concurrency)
        budget = self.cfg.l3_budget_s
        results: list[tuple[list[Hit], str]] = []
        timed_out = 0  # 预算耗尽时未完成的唯一变体数(标 partial,不放行)

        if workers == 1 and budget <= 0:
            # 纯串行、无预算(离线对照 / 调试)
            results = [_work(it) for it in uniq]
        else:
            from concurrent.futures import TimeoutError as _FTimeout, as_completed
            ex = ThreadPoolExecutor(max_workers=min(max(workers, 2), len(uniq)))
            try:
                futs = {ex.submit(_work, it): it for it in uniq}
                pending = set(futs)
                if budget and budget > 0:
                    deadline = t + budget
                    # 关键:as_completed 的 timeout 必须绑定「剩余预算」,否则单个卡死的
                    # presidio 请求会让 as_completed 阻塞越过预算,兜底失效(命门)。
                    try:
                        for fut in as_completed(futs, timeout=budget):
                            pending.discard(fut)
                            try:
                                results.append(fut.result())
                            except Exception:
                                # 单个变体扫描异常:按不可达处理(fail-closed 侧,绝不当 PASS)
                                results.append(([], "unreachable"))
                            if time.perf_counter() >= deadline:
                                break
                    except _FTimeout:
                        # 预算到点仍有 future 未完成:as_completed 抛超时,pending 里即未扫完的
                        pass
                    # 预算到点仍未回的:标 partial(→ incomplete → fail-closed),绝不静默放行
                    timed_out = len(pending)
                    for fut in pending:
                        fut.cancel()
                else:
                    for fut in as_completed(futs):
                        pending.discard(fut)
                        try:
                            results.append(fut.result())
                        except Exception:
                            results.append(([], "unreachable"))
            finally:
                # 不阻塞:已超预算就不等残余线程(它们在后台自然结束;结果不被采纳,无副作用)
                ex.shutdown(wait=False, cancel_futures=True)
        latency["L3"] = latency.get("L3", 0.0) + (time.perf_counter() - t) * 1000

        hits: list[Hit] = []
        for hits_local, worst in results:
            if worst == "unreachable":
                l3_state["down"] = True
                l3_state["incomplete"] = True
            else:
                if worst == "partial":
                    l3_state["incomplete"] = True
                l3_state["reached"] = True
                hits.extend(hits_local)
        # 预算截断:未完成变体覆盖不完整,标 incomplete(上层 fail-closed 升 BLOCK)
        if timed_out > 0:
            l3_state["incomplete"] = True
            l3_state["budget_truncated"] = l3_state.get("budget_truncated", 0) + timed_out
        return self._drop_rot13_pseudo(hits)

    # ---- 去重(§3 step4:同 dedup_key 合并,保留最高 confidence)----
    @staticmethod
    def _dedup(hits: list[Hit]) -> list[Hit]:
        best: dict[tuple, Hit] = {}
        for h in hits:
            k = h.dedup_key()
            if k not in best or h.confidence > best[k].confidence:
                best[k] = h
        return list(best.values())

    # ---- 聚合 verdict / top_layer(§2)----
    @staticmethod
    def _aggregate(hits: list[Hit]) -> tuple[Verdict, Layer | None]:
        block = [h for h in hits if h.action == Verdict.BLOCK]
        if block:
            deciding = block
            verdict = Verdict.BLOCK
        else:
            redact = [h for h in hits if h.action == Verdict.REDACT]
            if redact:
                deciding = redact
                verdict = Verdict.REDACT
            else:
                return Verdict.PASS, None
        top = min((h.layer for h in deciding), key=layer_rank)
        return verdict, top

    # ---- REDACT 文本生成(保结构合法)----
    def _build_redactions(self, hits: list[Hit]) -> list[tuple[str, str]]:
        """返回 [(matched, mask), ...],长串优先以免部分覆盖。"""
        pairs: dict[str, str] = {}
        for h in hits:
            if h.action == Verdict.REDACT and h.matched:
                pairs[h.matched] = self.cfg.redact_mask.format(entity=h.entity)
        return sorted(pairs.items(), key=lambda kv: len(kv[0]), reverse=True)

    def _redact_str(self, text: str, repl: list[tuple[str, str]]) -> str:
        for matched, mask in repl:
            text = text.replace(matched, mask)
        return text

    def _redact_obj(self, obj, repl: list[tuple[str, str]], _prefix: str = ""):
        # 脱敏作用域必须与扫描作用域对齐:未被扫描的子树(工具定义/协议字段/history)
        # 一律原样保留。否则全局字符串替换会把命中片段"顺带"改进协议字段——真机事故:
        # agentMode 被改写成 [REDACTED:LOCATION] → Kiro 400 Improperly formed request。
        if isinstance(obj, str):
            return self._redact_str(obj, repl)
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                p = f"{_prefix}.{k}" if _prefix else str(k)
                if k in extract._SKIP_SUBTREE_KEYS or p.endswith("conversationState.history"):
                    out[k] = v
                else:
                    out[k] = self._redact_obj(v, repl, p)
            return out
        if isinstance(obj, list):
            return [self._redact_obj(v, repl, f"{_prefix}[{i}]") for i, v in enumerate(obj)]
        return obj

    # ---- 入口 ----
    def scan(
        self,
        content,
        *,
        injection_point: InjectionPoint = InjectionPoint.PROMPT,
        run_async_l4: bool = False,
        session_window: list[str] | None = None,
    ) -> ScanResult:
        t_total = time.perf_counter()
        latency: dict[str, float] = {}
        notes: list[str] = []
        variants_sink: list[str] = []
        l3_state: dict = {}
        # L3 待扫变体全局收集(跨 unit),循环后去重+并发一次性扫,详见 _scan_l3_concurrent。
        l3_pending: list[tuple[str, str, str | None]] = []

        # 1. 抽取待扫文本单元
        units = extract.extract_units(content, injection_point)

        # session_window 仅套用于 str(prompt/flowback)主单元;MCP 叶子不逐个拼历史
        sw_for_units = session_window if isinstance(content, str) else None

        all_hits: list[Hit] = []

        # 2–3. 每个单元 → 变体 → L0/L1/L2/L3.5(同步),L3 候选登记进 l3_pending
        for text, field_path in units:
            all_hits.extend(
                self._scan_text_unit(
                    text, field_path, sw_for_units, latency, variants_sink, l3_pending
                )
            )

        # 3b. L3 全局去重 + 并发扫描(核心性能补丁:替代逐 unit×逐变体串行 Presidio)
        all_hits.extend(self._scan_l3_concurrent(l3_pending, latency, l3_state))

        # 通道管控(套件4):MCP/EGRESS 且 dict 入参
        if injection_point in (InjectionPoint.MCP, InjectionPoint.EGRESS) and isinstance(
            content, dict
        ):
            tool = content.get("tool")
            args = content.get("arguments", content.get("args"))
            if not isinstance(args, dict):
                args = {k: v for k, v in content.items() if k not in ("tool", "arguments", "args")}
            ch = egress.scan_channel(tool, args)
            if ch:
                all_hits.extend(ch)
                notes.append("通道管控兜底,非内容命中")

        # L3 缺席标注(D2b/D3):只要扫描过程中**任一**单元/变体出现不可达或部分语言失败,
        # L3 覆盖即不完整——绝不能因"曾经成功过一次"就当作真 PASS。
        # 保留 "L3 skipped" 子串以便 run_offline.py 的 _l3_absent() / §9 skip 逻辑匹配。
        if l3_state.get("incomplete"):
            if l3_state.get("down"):
                notes.append("L3 skipped(analyzer 不可达)——非 PASS,L3 应命中项在离线无 Presidio 时会判失败")
            elif l3_state.get("budget_truncated"):
                # 时间预算到点:部分唯一变体未扫完,覆盖不完整 → 非真 PASS,上层 fail-closed 升 BLOCK。
                # 保留 "L3 skipped" 子串以触发 server.py 的 fail-closed marker 匹配(D4)。
                notes.append(
                    f"L3 skipped(时间预算 {self.cfg.l3_budget_s}s 到点,{l3_state['budget_truncated']} 个变体未扫完)"
                    "——覆盖不完整,未扫变体的 PII 可能漏检,非真 PASS"
                )
            else:
                notes.append("L3 skipped(analyzer 部分语言失败)——覆盖不完整,失败语言的 PII 可能漏检,非真 PASS")

        # 4. 去重
        all_hits = self._dedup(all_hits)

        # 5. 聚合
        verdict, top_layer = self._aggregate(all_hits)

        # redacted_text
        redacted_text = None
        if verdict == Verdict.REDACT:
            repl = self._build_redactions(all_hits)
            if isinstance(content, str):
                redacted_text = self._redact_str(content, repl)
            elif isinstance(content, dict):
                redacted_text = json.dumps(
                    self._redact_obj(copy.deepcopy(content), repl), ensure_ascii=False
                )
            else:
                redacted_text = self._redact_str(str(content), repl)

            # 诚实标注(Defect B):REDACT 却一字未改 = 脱敏落空 —— 命中片段不在原文可见字面
            # (多因"含义保留"变体命中,如 normalize/stripped-sep 后的 matched 与原文不一致,
            # 或被 §4 收尾滤掉后仍有其它同类残留)。绝不静默放行:显式记录该 REDACT 未真正遮蔽。
            # 注:仅捕获"整体零改动"的落空;是否升级为 fail-closed BLOCK 待 fixtures 到位后定夺。
            original_repr = (
                content if isinstance(content, str)
                else json.dumps(content, ensure_ascii=False)
            )
            if redacted_text == original_repr:
                notes.append("REDACT 未生效(命中片段不在原文字面,脱敏落空)——非真 PASS,须人工复核")

        # 6. L4(仅异步告警,不改 verdict)
        async_alerts: list[AsyncAlert] = []
        if run_async_l4:
            t = time.perf_counter()
            l4_text = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)
            async_alerts = l4_semantic.analyze(
                l4_text, use_bedrock=self.cfg.use_bedrock_l4, model_key=self.cfg.l4_model_key
            )
            latency["L4"] = (time.perf_counter() - t) * 1000
        else:
            notes.append("L4 未在同步跑(生产为队列异步)")

        # 7. latency + 返回
        latency["total"] = (time.perf_counter() - t_total) * 1000

        # 变体去重保序(调试/审计)
        seen: set[str] = set()
        uniq_variants = [v for v in variants_sink if not (v in seen or seen.add(v))]

        return ScanResult(
            verdict=verdict,
            hits=all_hits,
            top_layer=top_layer,
            redacted_text=redacted_text,
            async_alerts=async_alerts,
            latency_ms={k: round(v, 3) for k, v in latency.items()},
            normalized_variants=uniq_variants,
            notes=notes,
        )
