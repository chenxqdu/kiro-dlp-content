#!/usr/bin/env python3
"""诊断探针 A — 取 Presidio 原始 NER 输出(绕过引擎过滤,看 analyzer 到底报了什么)。

用途:当某条 fixture 的 verdict 与期望不符、且命中里有 presidio:* 规则时,先用本
探针拿到 analyzer 的原始 entity/score/片段,再判断是引擎过滤问题还是 NER 误报。
本轮正是靠它坐实"en 模型把整句中文标 PERSON、恒 0.85 分"的根因(见 03 文档 §8.1)。

跑法(在实例上,容器内可达 presidio-analyzer:5002):
  sudo docker run --rm --network docker_default \
    -v $PWD/probe_presidio_raw.py:/tmp/probe.py:ro \
    kiro-dlp-engine:latest python3 /tmp/probe.py "要测的文本1" "要测的文本2"
不带参数时跑内置的套件6 四条(本轮排障现场)。
"""
import json
import sys
import urllib.request

ANALYZER = "http://presidio-analyzer:5002/analyze"

DEFAULT_CASES = [
    ("S6-01", "我们下个季度计划把华东区的获客成本压到行业均值的六成,渠道结构也要重排。"),
    ("S6-04", "今天天气不错,帮我把这段会议纪要润色得更正式一些,谢谢。"),
    ("S6-02", "把这版尚未公布的财务预测和上季度实际差异整理成一段对外口径。"),
    ("S6-03", "描述一下我们自研推荐引擎的召回排序两阶段是怎么协同的,越细越好。"),
]


def call(text: str, lang: str) -> list[dict]:
    payload = json.dumps({"text": text, "language": lang}).encode()
    req = urllib.request.Request(ANALYZER, data=payload,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=8) as r:
        return json.loads(r.read().decode())


def main() -> None:
    cases = ([(f"arg{i}", t) for i, t in enumerate(sys.argv[1:], 1)]
             if len(sys.argv) > 1 else DEFAULT_CASES)
    for tid, text in cases:
        print("====", tid, "====")
        for lang in ("en", "zh"):
            try:
                res = call(text, lang)
                if not res:
                    print(f"  [{lang}] (no hits)")
                for r in res:
                    frag = text[r["start"]:r["end"]]
                    print(f"  [{lang}] {r['entity_type']} "
                          f"score={r['score']:.3f} frag={frag!r}")
            except Exception as e:
                print(f"  [{lang}] ERROR {type(e).__name__}: {e}")


if __name__ == "__main__":
    main()
