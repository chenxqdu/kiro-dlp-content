"""MCP / 嵌套 JSON 展开(SPEC §6)。

把 content 抽成若干【文本单元 (text, field_path)】:
- str  → 单个单元, field_path=None
- dict → MCP 调用 {"tool","arguments":{...}}:递归展开所有字符串叶子,
         每个叶子带点号+下标路径 field_path。tool 名也扫(field_path="tool")。
数字/布尔/None 叶子跳过(不是待扫文本)。
"""
from __future__ import annotations

# 同义工具名归一(MCP-01):写文件类工具视作同一处理
_WRITE_SYNONYMS = {"write_file", "create_file", "edit_file", "put_file", "save_file"}


def canonical_tool(name: str | None) -> str | None:
    if not name:
        return None
    return "write_file" if name in _WRITE_SYNONYMS else name


def _walk(obj, prefix: str, out: list[tuple[str, str | None]]) -> None:
    if isinstance(obj, str):
        out.append((obj, prefix or None))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{prefix}.{k}" if prefix else str(k)
            _walk(v, p, out)
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _walk(v, f"{prefix}[{i}]", out)
    # int/float/bool/None → 跳过


def extract_units(content, injection_point=None) -> list[tuple[str, str | None]]:
    """返回 [(text, field_path), ...]。"""
    if isinstance(content, str):
        return [(content, None)]

    out: list[tuple[str, str | None]] = []
    if isinstance(content, dict):
        tool = content.get("tool")
        if isinstance(tool, str):
            out.append((tool, "tool"))
        args = content.get("arguments", content.get("args", {}))
        _walk(args, "", out)
        # 有些 MCP 形态把参数直接摊在顶层(无 arguments 包裹)
        if not args and not tool:
            _walk(content, "", out)
    else:
        _walk(content, "", out)
    return out
