"""JS 词法分析:把脚本切成 token,并解码字符串/模板/正则中的转义。

不做完整解析——只做足够支撑静态判定的词法,以便:
* 折叠字符串拼接(``"ev"+"al"``)与常见解码调用(``atob``/``fromCharCode``);
* 识别 ``document["coo"+"kie"]`` 这类计算成员访问;
* 发现模板字面量里的动态拼接。

对无法正确处理的极端输入保持安全降级(返回 None,由调用方按可疑处理)。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

KEYWORDS = frozenset(
    """break case catch class const continue debugger default delete do else export
    extends finally for function if import in instanceof let new return super switch
    this throw try typeof var void while with yield async await of static get set
    null true false undefined NaN Infinity""".split()
)

# 这些 token 之后出现的 '/' 是正则开始,而不是除号。
_REGEX_PRECEDERS_PUNCT = frozenset("(,=:[!&|?{};+-*%<>~^")
_REGEX_PRECEDERS_KW = frozenset(
    "return typeof case do else in instanceof new delete void throw yield await of".split()
)

_IDENT_START = re.compile(r"[A-Za-z_$\u0080-￿]")
_IDENT_PART = re.compile(r"[A-Za-z0-9_$\u0080-￿]")
_NUMBER_RE = re.compile(
    r"0[xX][0-9a-fA-F_]+n?|0[oO][0-7_]+n?|0[bB][01_]+n?|"
    r"(?:\d[\d_]*\.?[\d_]*|\.\d[\d_]*)(?:[eE][+-]?\d+)?n?"
)
_SIMPLE_ESCAPES = {
    "n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v",
    "0": "\0", "'": "'", '"': '"', "\\": "\\", "/": "/", "`": "`",
}


@dataclass
class Token:
    kind: str          # ident | keyword | punct | string | template | number | regex
    value: str         # 解码后的值(字符串/模板/标识符/操作符)
    start: int
    end: int
    raw: str = ""
    quasis: Optional[List[str]] = None   # template 的静态片段
    exprs: Optional[List[str]] = None    # template 的 ${...} 源码
    synthetic: bool = False              # 由折叠产生

    def is_punct(self, *vals: str) -> bool:
        return self.kind == "punct" and self.value in vals

    def is_ident(self, *vals: str) -> bool:
        if self.kind == "keyword" and self.value in vals:
            return True
        return self.kind == "ident" and (not vals or self.value in vals)


def _decode_escaped(src: str, quote: str) -> Tuple[str, int]:
    """解码 JS 字符串内容(不含两端引号)。返回 (值, 转义数量)。"""
    out: List[str] = []
    esc = 0
    i = 0
    n = len(src)
    while i < n:
        ch = src[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        esc += 1
        i += 1
        if i >= n:
            break
        c = src[i]
        if c == "\n":            # 续行
            i += 1
        elif c == "\r":
            i += 2 if (i + 1 < n and src[i + 1] == "\n") else 1
        elif c in _SIMPLE_ESCAPES:
            out.append(_SIMPLE_ESCAPES[c])
            i += 1
        elif c == "x":
            hx = src[i + 1 : i + 3]
            if len(hx) == 2 and all(h in "0123456789abcdefABCDEF" for h in hx):
                out.append(chr(int(hx, 16)))
                i += 3
            else:
                out.append("x")
                i += 1
        elif c == "u":
            if i + 1 < n and src[i + 1] == "{":
                j = src.find("}", i + 2)
                hx = src[i + 2 : j] if j != -1 else ""
                if j != -1 and hx and all(h in "0123456789abcdefABCDEF" for h in hx):
                    try:
                        out.append(chr(int(hx, 16)))
                    except (ValueError, OverflowError):
                        pass
                    i = j + 1
                else:
                    out.append("u")
                    i += 1
            else:
                hx = src[i + 1 : i + 5]
                if len(hx) == 4 and all(h in "0123456789abcdefABCDEF" for h in hx):
                    out.append(chr(int(hx, 16)))
                    i += 5
                else:
                    out.append("u")
                    i += 1
        elif c in "01234567":    # 八进制(宽松模式)
            j = i
            while j < n and j < i + 3 and src[j] in "01234567":
                j += 1
            try:
                out.append(chr(int(src[i:j], 8)))
            except ValueError:
                pass
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out), esc


def _read_string(src: str, i: int) -> Tuple[Optional[str], int, str, int]:
    """从引号处读取字符串。返回 (解码值, 结束位置, 原文, 转义数)。"""
    quote = src[i]
    j = i + 1
    n = len(src)
    while j < n:
        c = src[j]
        if c == "\\":
            j += 2
            continue
        if c == quote:
            inner = src[i + 1 : j]
            val, esc = _decode_escaped(inner, quote)
            return val, j + 1, src[i : j + 1], esc
        if c == "\n":  # 未闭合字符串
            return None, i, src[i:j], 0
        j += 1
    return None, i, src[i:n], 0


def _read_template(src: str, i: int) -> Tuple[Optional[Token], int]:
    """读取模板字面量,分离静态片段与 ${...} 表达式源码。"""
    n = len(src)
    j = i + 1
    quasis: List[str] = []
    exprs: List[str] = []
    buf: List[str] = []
    esc = 0
    while j < n:
        c = src[j]
        if c == "\\":
            buf.append(src[j : j + 2])
            j += 2
            continue
        if c == "`":
            quasis.append(_decode_escaped("".join(buf), "`")[0])
            return (
                Token(
                    "template",
                    "",
                    i,
                    j + 1,
                    src[i : j + 1],
                    quasis=quasis,
                    exprs=exprs,
                ),
                j + 1,
            )
        if c == "$" and j + 1 < n and src[j + 1] == "{":
            quasis.append(_decode_escaped("".join(buf), "`")[0])
            buf = []
            # 扫描到匹配的 }
            k = j + 2
            depth = 1
            expr_start = k
            while k < n and depth > 0:
                ch = src[k]
                if ch in "'\"":
                    _, k2, _, _ = _read_string(src, k)
                    k = k2 if k2 > k else k + 1
                    continue
                if ch == "`":
                    t, k2 = _read_template(src, k)
                    k = k2 if k2 > k else k + 1
                    continue
                if ch == "/" and k + 1 < n and src[k + 1] == "/":
                    nl = src.find("\n", k)
                    k = n if nl == -1 else nl
                    continue
                if ch == "/" and k + 1 < n and src[k + 1] == "*":
                    endc = src.find("*/", k + 2)
                    k = n if endc == -1 else endc + 2
                    continue
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        break
                k += 1
            exprs.append(src[expr_start:k])
            j = k + 1 if k < n else n
            continue
        buf.append(c)
        j += 1
    return None, i


def _read_regex(src: str, i: int) -> Tuple[Optional[str], int]:
    n = len(src)
    j = i + 1
    in_class = False
    while j < n:
        c = src[j]
        if c == "\\":
            j += 2
            continue
        if c == "[":
            in_class = True
        elif c == "]":
            in_class = False
        elif c == "/" and not in_class:
            j += 1
            while j < n and src[j].isalpha():
                j += 1
            return src[i:j], j
        elif c == "\n":
            return None, i
        j += 1
    return None, i


def tokenize(src: str, *, max_tokens: int = 2_000_000) -> List[Token]:
    """把源码切成 token(注释丢弃)。无法词法化的部分被跳过。"""
    tokens: List[Token] = []
    i = 0
    n = len(src)
    prev: Optional[Token] = None
    while i < n and len(tokens) < max_tokens:
        c = src[i]
        if c in " \t\r\n\f\v ﻿":
            i += 1
            continue
        # 注释
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            nl = src.find("\n", i)
            i = n if nl == -1 else nl + 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            end = src.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue
        # HTML 注释式(旧式脚本)
        if src.startswith("<!--", i):
            nl = src.find("\n", i)
            i = n if nl == -1 else nl + 1
            continue
        # 字符串
        if c in "'\"":
            val, end, raw, esc = _read_string(src, i)
            if val is None:
                i = end + 1
                continue
            tok = Token("string", val, i, end, raw)
            tokens.append(tok)
            prev = tok
            i = end
            continue
        # 模板
        if c == "`":
            tok, end = _read_template(src, i)
            if tok is None:
                i += 1
                continue
            tokens.append(tok)
            prev = tok
            i = end
            continue
        # 正则
        if c == "/":
            regex_ok = (
                prev is None
                or (prev.kind == "punct" and prev.value in _REGEX_PRECEDERS_PUNCT)
                or (prev.kind == "keyword" and prev.value in _REGEX_PRECEDERS_KW)
            )
            if regex_ok:
                raw, end = _read_regex(src, i)
                if raw is not None:
                    tok = Token("regex", raw, i, end, raw)
                    tokens.append(tok)
                    prev = tok
                    i = end
                    continue
            tok = Token("punct", "/", i, i + 1, "/")
            tokens.append(tok)
            prev = tok
            i += 1
            continue
        # 标识符 / 关键字
        if _IDENT_START.match(c) or (c == "\\" and src.startswith("\\u", i)):
            j = i
            val_parts: List[str] = []
            while j < n:
                ch = src[j]
                if ch == "\\" and src.startswith("\\u", j):
                    if j + 2 < n and src[j + 2] == "{":
                        k = src.find("}", j + 3)
                        hx = src[j + 3 : k] if k != -1 else ""
                        if k != -1 and hx and all(h in "0123456789abcdefABCDEF" for h in hx):
                            try:
                                val_parts.append(chr(int(hx, 16)))
                            except (ValueError, OverflowError):
                                pass
                            j = k + 1
                            continue
                    hx = src[j + 2 : j + 6]
                    if len(hx) == 4 and all(h in "0123456789abcdefABCDEF" for h in hx):
                        val_parts.append(chr(int(hx, 16)))
                        j += 6
                        continue
                    val_parts.append(ch)
                    j += 1
                    continue
                if (j == i and _IDENT_START.match(ch)) or (j > i and _IDENT_PART.match(ch)):
                    val_parts.append(ch)
                    j += 1
                    continue
                break
            if j == i:
                j = i + 1
            value = "".join(val_parts)
            kind = "keyword" if value in KEYWORDS else "ident"
            tok = Token(kind, value, i, j, src[i:j])
            tokens.append(tok)
            prev = tok
            i = j
            continue
        # 数字
        m = _NUMBER_RE.match(src, i)
        if m and m.end() > i:
            tok = Token("number", m.group(0), i, m.end(), m.group(0))
            tokens.append(tok)
            prev = tok
            i = m.end()
            continue
        # 标点(含最长匹配)
        for plen in (4, 3, 2):
            piece = src[i : i + plen]
            if piece in ("===", "!==", ">>>", "**=", "<<=", ">>=", "&&=", "||=", "??=",
                         "...", "=>", "==", "!=", "<=", ">=", "&&", "||", "??", "+=",
                         "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<", ">>", "**",
                         "++", "--", "?."):
                tok = Token("punct", piece, i, i + plen, piece)
                tokens.append(tok)
                prev = tok
                i += plen
                break
        else:
            tok = Token("punct", c, i, i + 1, c)
            tokens.append(tok)
            prev = tok
            i += 1
    return tokens


def tokens_to_text(tokens: List[Token]) -> str:
    return " ".join(t.value if t.kind != "template" else (t.raw or "") for t in tokens)
