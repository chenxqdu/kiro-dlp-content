#!/usr/bin/env python3
"""诊断探针 B — 按引擎变体展开(raw/normalized/stripped-sep/decoded:*)逐变体 × 逐语言
取 Presidio 原始命中,精确归因"误报发生在哪个预处理变体上"。

本轮用它坐实套件2 八条误报的完整归因矩阵(S2-02..S2-16;例如 S2-08 的 PERSON 误报
出现在 raw 与 decoded:base64 两个变体、S2-16 的 LOCATION 出现在 stripped-sep)——
这是决定"修引擎过滤器而非改 fixture"的关键证据。

跑法(在实例上,需挂 engine 源码以复用 dlp.normalize):
  sudo docker run --rm --network docker_default \
    -v /home/ec2-user/kiro-dlp/engine:/app/engine \
    -v $PWD/probe_presidio_variants.py:/tmp/probe.py:ro \
    kiro-dlp-engine:latest python3 /tmp/probe.py suite2 S2-02 S2-14
参数:<suiteN> [用例ID...](缺省=该套件全部)。
"""
import json
import sys
import urllib.request

sys.path.insert(0, "/app/engine")
from dlp import normalize  # noqa: E402

ANALYZER = "http://presidio-analyzer:5002/analyze"
FIXTURE_DIR = "/app/engine/tests/fixtures"


def call(text: str, lang: str) -> list[dict]:
    payload = json.dumps({"text": text, "language": lang}).encode()
    req = urllib.request.Request(ANALYZER, data=payload,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=8) as r:
        return json.loads(r.read().decode())


def variants(text: str) -> list[tuple[str, str]]:
    """与 engine._labeled_variants 同构(不含 session-window/folded,探针够用)。"""
    out = [("raw", text)]
    n = normalize.normalize(text)
    if n != text:
        out.append(("normalized", n))
    s = normalize.strip_separators(n)
    if s != n:
        out.append(("stripped-sep", s))
    for v, kind in normalize.decode_variants(n):
        out.append((f"decoded:{kind}", v))
    return out


def main() -> None:
    suite = sys.argv[1] if len(sys.argv) > 1 else "suite2"
    only = set(sys.argv[2:])
    fixtures = json.load(open(f"{FIXTURE_DIR}/{suite}.json"))
    for d in fixtures:
        if only and d["id"] not in only:
            continue
        content = d["content"]
        if not isinstance(content, str):
            print("====", d["id"], "==== (非 str content,跳过)")
            continue
        print("====", d["id"], "====")
        for src, vt in variants(content):
            for lang in ("en", "zh"):
                try:
                    for r in call(vt, lang):
                        frag = vt[r["start"]:r["end"]]
                        print(f"  [{src}/{lang}] {r['entity_type']} "
                              f"{r['score']:.2f} frag={frag!r}"[:110])
                except Exception as e:
                    print(f"  [{src}/{lang}] ERR {type(e).__name__}")


if __name__ == "__main__":
    main()
