"""安全加载 .ipynb 的 JSON,抵御 JSON 炸弹与解析差异攻击。

威胁:
* 超大文件 / 超深嵌套 → 内存或递归耗尽。
* 重复键:Python 的 json 保留最后一个,而别的解析器可能保留第一个,
  攻击者可借此让扫描器看到干净内容、渲染器执行恶意内容。
* ``NaN`` / ``Infinity``:非标准 JSON,不同平台表现不一致。
* 超量节点(数百万个空数组)造成 DoS。
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple


class NotebookRejected(Exception):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


def _check_tree(obj: Any, max_depth: int, max_nodes: int) -> None:
    """迭代式遍历,避免递归导致的栈溢出。"""
    nodes = 0
    # (obj, depth)
    stack: List[Tuple[Any, int]] = [(obj, 1)]
    while stack:
        cur, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            raise NotebookRejected(
                "structure-too-large", f"JSON 节点数超过上限 {max_nodes}"
            )
        if depth > max_depth:
            raise NotebookRejected(
                "nesting-too-deep", f"JSON 嵌套深度超过上限 {max_depth}"
            )
        if isinstance(cur, dict):
            for k, v in cur.items():
                if isinstance(v, (dict, list)):
                    stack.append((v, depth + 1))
        elif isinstance(cur, list):
            for v in cur:
                if isinstance(v, (dict, list)):
                    stack.append((v, depth + 1))


def loads_notebook(
    raw: Any,
    *,
    max_bytes: int = 32 * 1024 * 1024,
    max_depth: int = 200,
    max_nodes: int = 4_000_000,
) -> Tuple[Any, List[str]]:
    """解析笔记本 JSON,返回 (对象, 警告列表)。

    失败时抛 :class:`NotebookRejected`。
    """
    warnings: List[str] = []

    if isinstance(raw, bytes):
        if len(raw) > max_bytes:
            raise NotebookRejected(
                "file-too-large", f"文件 {len(raw)} 字节,上限 {max_bytes}"
            )
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise NotebookRejected("not-utf8", str(exc)) from exc
    elif isinstance(raw, str):
        if len(raw.encode("utf-8", "ignore")) > max_bytes:
            raise NotebookRejected("file-too-large", "文本长度超限")
        if raw.startswith("﻿"):
            raw = raw[1:]
        text = raw
    else:
        raise NotebookRejected("bad-input", "输入必须是 bytes 或 str")

    dup_keys: List[str] = []

    def _pairs(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for k, v in pairs:
            if k in out:
                dup_keys.append(k)
                # 保留第一个,与渲染器常见的"首次出现"语义一致,
                # 同时记录以便告警(绝不静默取其一)。
                continue
            out[k] = v
        return out

    def _const(name: str) -> Any:
        raise NotebookRejected("non-standard-json", f"包含非标准常量 {name}")

    try:
        obj = json.loads(text, object_pairs_hook=_pairs, parse_constant=_const)
    except NotebookRejected:
        raise
    except RecursionError as exc:
        raise NotebookRejected("nesting-too-deep", "JSON 解析递归过深") from exc
    except json.JSONDecodeError as exc:
        raise NotebookRejected(
            "invalid-json", f"第 {exc.lineno} 行第 {exc.colno} 列: {exc.msg}"
        ) from exc

    if dup_keys:
        # 去重后仍重复出现 → 解析歧义,属于可疑篡改。
        uniq = sorted(set(dup_keys))
        warnings.append(
            "duplicate-json-keys: 检测到重复键 "
            + ", ".join(uniq[:10])
            + ("…" if len(uniq) > 10 else "")
        )

    if not isinstance(obj, dict):
        raise NotebookRejected("not-an-object", "笔记本顶层必须是 JSON 对象")

    _check_tree(obj, max_depth, max_nodes)
    return obj, warnings
