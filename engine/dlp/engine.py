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

    # ---- 内容层扫描:一个文本单元 → 多变体 → L0..L3.5 ----
    def _scan_text_unit(
        self,
        text: str,
        field_path: str | None,
        session_window: list[str] | None,
        latency: dict[str, float],
        variants_sink: list[str],
        l3_state: dict,
    ) -> list[Hit]:
        hits: list[Hit] = []
        variants = self._labeled_variants(text, session_window)
        l3_scanned: set[str] = set()

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
            for h in l2_entropy.scan(variant, source=src):
                h.field_path = field_path
                hits.append(h)
            latency["L2"] = latency.get("L2", 0.0) + (time.perf_counter() - t) * 1000

            # L3 Presidio:HTTP 昂贵。仅当 analyzer **完全掉线**(down)才短路后续调用;
            # partial(部分语言失败但 analyzer 在线)不短路——后续变体仍可能被成功识别(D2)。
            run_l3 = self.cfg.run_l3_on_all_variants or src in ("raw", "normalized")
            if run_l3 and not l3_state.get("down") and variant not in l3_scanned:
                l3_scanned.add(variant)
                t = time.perf_counter()
                l3_hits, status = l3_presidio.scan(
                    variant, source=src, languages=self.cfg.presidio_languages
                )
                latency["L3"] = latency.get("L3", 0.0) + (time.perf_counter() - t) * 1000
                if status == "unreachable":
                    # 全语言失败 → analyzer 掉线:标 down(短路)+ incomplete(触发缺席标注)。
                    l3_state["down"] = True
                    l3_state["incomplete"] = True
                else:
                    if status == "partial":
                        # analyzer 在线但部分语言缺席 → 覆盖不完整,仍须触发缺席标注(D2b/D3)。
                        l3_state["incomplete"] = True
                    l3_state["reached"] = True
                    for h in l3_hits:
                        h.field_path = field_path
                        hits.append(h)

            t = time.perf_counter()
            for h in l35_glossary.scan(variant, source=src):
                h.field_path = field_path
                hits.append(h)
            latency["L3.5"] = latency.get("L3.5", 0.0) + (time.perf_counter() - t) * 1000

        # §4 收尾:剔除 rot13 变体"变造"出的伪 PII。
        # rot13 是全文对合变换(自身即逆):对良性明文(如 alice@example.com)整体 rot13
        # 会得到 nyvpr@rknzcyr.pbz 这类"看着像真值、实则原文不存在"的串,骗过 L0 保留域名
        # 白名单 / 诱使 Presidio 误报 PERSON —— 正是 §4 所指"解出乱码→丢弃,不产生噪声"。
        # rot13 的正当用途只有一个:还原攻击者用 rot13 藏起来的【凭证】(BLOCK 级,套件3
        # 编码规避),这类必须保留。故 rot13 变体只认 BLOCK 级命中,REDACT 级一律当噪声丢弃:
        #   · 保 FP-06(alice@example.com→PASS)、套件2 零误报;
        #   · 不回归:被 rot13 藏起来的真 AKIA/PEM 仍解得出并 BLOCK。
        # 判据用 h.source(已按预处理路径精确标注),不误伤 normalized/base64/hex 等
        # "含义保留"变体里的真实 PII(如 EVA-11 中文数字身份证走 normalized,不受影响)。
        hits = [
            h
            for h in hits
            if not (h.source == "decoded:rot13" and h.action is not Verdict.BLOCK)
        ]
        return hits

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

    def _redact_obj(self, obj, repl: list[tuple[str, str]]):
        if isinstance(obj, str):
            return self._redact_str(obj, repl)
        if isinstance(obj, dict):
            return {k: self._redact_obj(v, repl) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._redact_obj(v, repl) for v in obj]
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

        # 1. 抽取待扫文本单元
        units = extract.extract_units(content, injection_point)

        # session_window 仅套用于 str(prompt/flowback)主单元;MCP 叶子不逐个拼历史
        sw_for_units = session_window if isinstance(content, str) else None

        all_hits: list[Hit] = []

        # 2–3. 每个单元 → 变体 → L0..L3.5
        for text, field_path in units:
            all_hits.extend(
                self._scan_text_unit(
                    text, field_path, sw_for_units, latency, variants_sink, l3_state
                )
            )

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
