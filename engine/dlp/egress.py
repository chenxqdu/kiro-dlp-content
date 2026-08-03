"""通道管控(SPEC §6 egress)—— 套件4。

纯内容扫描对"read-then-exfil / $VAR 解引用 / git push 非白名单 / execute_sql
非 allowlist / code_search remote:true"结构上检不到 —— 这里做 default-deny 语义的
引擎侧模拟:命中 → Hit(layer=L0, entity="EGRESS_*", action=BLOCK) 并在 notes 注明
"通道管控兜底,非内容命中"。
"""
from __future__ import annotations

import re

from .extract import canonical_tool
from .types import Hit, Layer, Verdict

# 出口白名单(default-deny:不在名单内即拦)
GIT_REMOTE_ALLOWLIST = ("git.corp.example.net", "codecommit", "internal-git")
SQL_CONN_ALLOWLIST = ("analytics-ro", "reporting-replica")

# read-then-exfil 特征:cat/read 文件后经网络外发
_READ_THEN_EXFIL = re.compile(
    r"(cat|type|less|head|tail)\b.*\|\s*(curl|wget|nc|ncat|http)",
    re.IGNORECASE | re.DOTALL,
)
_CURL_DATA_FILE = re.compile(r"curl\b.*(--data-binary|--data|-d)\s+@?\S+", re.IGNORECASE)
_VAR_DEREF = re.compile(r"\$\{?\w+\}?")
_GIT_PUSH = re.compile(r"git\s+push\s+(\S+)", re.IGNORECASE)
_CURL_URL = re.compile(r"(?:curl|wget)\b[^\n|]*\bhttps?://([^/\s]+)", re.IGNORECASE)


def _note(hits: list[Hit]) -> str:
    return "通道管控兜底,非内容命中" if hits else ""


def scan_channel(tool: str | None, args: dict, field_prefix: str = "") -> list[Hit]:
    """按工具类型做通道判定。返回 EGRESS_* hits。"""
    hits: list[Hit] = []
    tool = canonical_tool(tool) or (tool or "")

    def _blk(entity, path, matched):
        hits.append(Hit(Layer.L0, f"egress_channel", entity, (-1, -1),
                        matched, Verdict.BLOCK, source="channel", field_path=path))

    # shell / exec 类
    cmd = ""
    for k in ("command", "cmd", "script", "shell"):
        v = args.get(k)
        if isinstance(v, str):
            cmd = v
            break
    if cmd:
        if _READ_THEN_EXFIL.search(cmd):
            _blk("EGRESS_READ_EXFIL", f"{field_prefix}command", cmd)
        if _CURL_DATA_FILE.search(cmd):
            _blk("EGRESS_DATA_UPLOAD", f"{field_prefix}command", cmd)
        m = _GIT_PUSH.search(cmd)
        if m:
            remote = m.group(1)
            if not any(a in remote for a in GIT_REMOTE_ALLOWLIST):
                _blk("EGRESS_GIT_PUSH", f"{field_prefix}command", remote)
        for m in _CURL_URL.finditer(cmd):
            host = m.group(1)
            if not host.endswith("corp.example.net"):
                _blk("EGRESS_HTTP", f"{field_prefix}command", host)

    # execute_sql:connection 不在 allowlist
    if tool in ("execute_sql", "run_query", "sql"):
        conn = args.get("connection") or args.get("conn") or args.get("database") or ""
        if isinstance(conn, str) and conn and not any(a in conn for a in SQL_CONN_ALLOWLIST):
            _blk("EGRESS_SQL_CONN", f"{field_prefix}connection", conn)

    # code_search remote:true → 代码检索外发
    if tool in ("code_search", "search_code", "grep_repo"):
        if args.get("remote") in (True, "true", "True"):
            _blk("EGRESS_CODE_SEARCH", f"{field_prefix}remote", "remote:true")

    # git push 作为独立工具
    if tool in ("git_push", "push"):
        remote = args.get("remote") or args.get("url") or ""
        if isinstance(remote, str) and remote and not any(a in remote for a in GIT_REMOTE_ALLOWLIST):
            _blk("EGRESS_GIT_PUSH", f"{field_prefix}remote", remote)

    return hits
