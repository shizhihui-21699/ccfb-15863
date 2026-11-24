"""JS 静态判定:敏感 sink、凭证访问、外传目标、动态代码与混淆信号。

策略是"证据组合"而非单一关键词:
* 仅有 ``fetch`` → 图表加载数据,低风险;
* ``document.cookie`` + ``fetch`` → 凭证外传,高危;
* ``eval(atob(...))`` / ``Function`` 动态构造 → 高危;
* 网络目标不在白名单主机 → 高危(在 balanced/strict 下)。
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from . import jslex, patterns
from .model import Severity
from .policy import Policy

# --- 特征表 -------------------------------------------------------------

EVAL_SINKS = {"eval"}
FUNCTION_CTORS = {"Function"}
TIMER_FUNCS = {"setTimeout", "setInterval", "setImmediate"}
CODE_WRITE_SINKS = {
    "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
    "document.writeln", "srcdoc", "createContextualFragment", "setAttribute",
}
NETWORK_SINKS = {
    "fetch", "XMLHttpRequest", "sendBeacon", "WebSocket", "EventSource",
    "open", "importScripts",
}
NAV_SINKS = {"assign", "replace", "submit", "open", "navigate"}
STORAGE_SINKS = {
    "cookie", "localStorage", "sessionStorage", "indexedDB", "name",
    "clipboard", "credentials",
}
DECODER_FUNCS = {"atob", "unescape", "decodeURIComponent", "decodeURI", "fromCharCode"}

# 用来判定"混淆"的异常特征
_MANY_ESCAPES_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})")
_HEX_IDENT_RE = re.compile(r"\\u[0-9a-fA-F]{4}")
_LONG_CONCAT_RE = re.compile(r"""(["'])(?:\\.|(?!\1).){1,8}\1\s*\+\s*(["'])""")

@dataclass
class JsVerdict:
    severity: Severity = Severity.INFO
    reasons: List[str] = field(default_factory=list)
    sinks: Set[str] = field(default_factory=set)
    secrets: Set[str] = field(default_factory=set)
    remote_hosts: Set[str] = field(default_factory=set)
    has_eval: bool = False
    has_dynamic: bool = False
    decode_used: bool = False
    obfuscated: bool = False
    decoded_preview: str = ""

    @property
    def malicious(self) -> bool:
        return self.severity >= Severity.HIGH

    def summary(self) -> str:
        bits = [f"severity={self.severity.label}"]
        if self.sinks:
            bits.append("sinks=" + ",".join(sorted(self.sinks)[:8]))
        if self.secrets:
            bits.append("secrets=" + ",".join(sorted(self.secrets)[:6]))
        if self.remote_hosts:
            bits.append("hosts=" + ",".join(sorted(self.remote_hosts)[:6]))
        if self.has_eval:
            bits.append("eval")
        if self.has_dynamic:
            bits.append("dynamic-code")
        if self.obfuscated:
            bits.append("obfuscated")
        return "; ".join(bits)


def _raise(sev: Severity, cur: Severity) -> Severity:
    return sev if sev > cur else cur


class JsAnalyzer:
    def __init__(self, policy: Policy, max_chars: int = 4 * 1024 * 1024) -> None:
        self.policy = policy
        self.max_chars = max_chars

    # -- 公开入口 ---------------------------------------------------------
    def analyze(self, code: str) -> JsVerdict:
        v = JsVerdict()
        if not code or not code.strip():
            return v
        if len(code) > self.max_chars:
            v.severity = _raise(Severity.HIGH, v.severity)
            v.reasons.append(f"脚本超过 {self.max_chars} 字符,无法完整分析")
            v.has_dynamic = True
            return v

        tokens = jslex.tokenize(code)
        folded = self._fold(tokens)
        layers: List[Tuple[str, str]] = [("raw", code)]
        if folded.text and folded.text != code:
            layers.append(("folded", folded.text))

        # 解码 atob / fromCharCode 字面量
        decoded = self._decode_literals(tokens)
        for d in decoded:
            layers.append(("decoded", d))
            if not v.decoded_preview:
                v.decoded_preview = d[:160]

        # 解码文本里的编码块(分段拼接的载荷)
        for _, text in list(layers):
            for hit in patterns.find_encoded_blobs(text, limit=400_000, max_hits=8):
                if hit.looks_like in ("js", "html"):
                    layers.append((f"blob-{hit.kind}", hit.decoded_preview))
                    v.obfuscated = True

        # 混淆信号
        if len(_MANY_ESCAPES_RE.findall(code)) >= 24 or len(_HEX_IDENT_RE.findall(code)) >= 8:
            v.obfuscated = True
            v.reasons.append("大量十六进制/Unicode 转义")
        if len(_LONG_CONCAT_RE.findall(code)) >= 12:
            v.obfuscated = True
            v.reasons.append("大量短字符串拼接(疑似绕过关键词扫描)")

        for label, text in layers:
            self._scan_layer(text, label, v)

        self._feature_signals(code, tokens, v)
        return v

    # -- 单层扫描 ---------------------------------------------------------
    def _scan_layer(self, text: str, label: str, v: JsVerdict) -> None:
        low = text.lower()

        for tok in patterns.SECRET_TOKENS:
            if tok.lower() in low:
                v.secrets.add(tok)

        # eval / Function 动态构造
        if re.search(r"\beval\s*\(", text):
            v.sinks.add("eval")
            v.has_eval = True
            v.severity = _raise(Severity.HIGH, v.severity)
            v.reasons.append(f"[{label}] 使用 eval()")
        if re.search(r"\bnew\s+Function\s*\(", text) or re.search(r"\bFunction\s*\(\s*['\"]", text):
            v.sinks.add("Function")
            v.has_eval = True
            v.severity = _raise(Severity.HIGH, v.severity)
            v.reasons.append(f"[{label}] 使用 Function 构造器动态执行代码")
        if re.search(r"\bset(?:Timeout|Interval)\s*\(\s*['\"`]", text):
            v.sinks.add("timer-string")
            v.has_dynamic = True
            v.severity = _raise(Severity.MEDIUM, v.severity)
            v.reasons.append(f"[{label}] 以字符串形式调用计时器")
        if re.search(r"\bset(?:Timeout|Interval)\s*\([^)]*\beval\b", text):
            v.sinks.add("timer-eval")
            v.has_dynamic = True
            v.severity = _raise(Severity.HIGH, v.severity)
            v.reasons.append(f"[{label}] 计时器回调中执行 eval")

        # 代码写入 sink
        for s in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"):
            if re.search(r"\b" + re.escape(s) + r"\b", text):
                v.sinks.add(s)
        if re.search(r"\bdocument\s*\.\s*write", low):
            v.reasons.append(f"[{label}] 使用 document.write 注入标记")
            v.severity = _raise(Severity.MEDIUM, v.severity)

        # 弹窗/UI 欺骗类:非外传,但内联输出里出现即为可疑
        if re.search(r"\b(?:alert|confirm|prompt)\s*\(", text):
            v.sinks.add("ui-dialog")
            v.severity = _raise(Severity.MEDIUM, v.severity)
            v.reasons.append(f"[{label}] 触发浏览器对话框 alert/confirm/prompt")

        # 网络 sink(用单词边界,避免 prefetch/fetchData 之类误命中)
        net = False
        _NET_PATTERNS = {
            "fetch": r"\bfetch\s*\(",
            "XMLHttpRequest": r"\bXMLHttpRequest\b",
            "sendBeacon": r"\bsendBeacon\s*\(",
            "WebSocket": r"\bWebSocket\s*\(",
            "EventSource": r"\bEventSource\s*\(",
        }
        for name, pat in _NET_PATTERNS.items():
            if re.search(pat, text):
                v.sinks.add(name)
                net = True
        if re.search(r"\bnew\s+Image\b|\.src\s*=", text):
            v.sinks.add("image-beacon")
            net = True
        if re.search(r"\b(?:location|window\.location|top\.location)\s*(?:=|\.href\s*=|\.assign\s*\()", text):
            v.sinks.add("navigation")
            net = True
        if re.search(r"\bform\w*\s*\.\s*submit\s*\(", text):
            v.sinks.add("form-submit")
            net = True
        if re.search(r"\b(?:import|importScripts)\s*\(", text):
            v.sinks.add("dynamic-import")
            net = True

        # 提取 URL 主机并核对白名单
        for url in _URLS_RE.findall(text):
            info = patterns.classify_url(url)
            if info.scheme in ("http", "https") and info.host:
                v.remote_hosts.add(info.host)
                if not patterns.host_allowed(info.host, self.policy.data_hosts):
                    v.severity = _raise(Severity.HIGH, v.severity)
                    v.reasons.append(f"[{label}] 向非白名单主机发起请求: {info.host}")
            elif info.scheme in ("ws", "wss"):
                v.remote_hosts.add(info.host)
                v.severity = _raise(Severity.HIGH, v.severity)
                v.reasons.append(f"[{label}] WebSocket 连接: {info.host}")

        # 凭证 + 外传 = 高危
        if v.secrets and net:
            v.severity = _raise(Severity.CRITICAL, v.severity)
            v.reasons.append(
                f"[{label}] ��时读取凭证/存储并外传: "
                + ", ".join(sorted(v.secrets)[:5])
            )
        elif v.secrets:
            v.severity = _raise(Severity.MEDIUM, v.severity)
            v.reasons.append(f"[{label}] 访问凭证/本地存储: " + ", ".join(sorted(v.secrets)[:5]))

        # 动态代码
        if re.search(r"\b(?:atob|unescape|decodeURIComponent)\s*\(", text) and re.search(
            r"\b(?:eval|Function|innerHTML|document\.write)\b", text
        ):
            v.has_dynamic = True
            v.severity = _raise(Severity.HIGH, v.severity)
            v.reasons.append(f"[{label}] 解码后动态执行(疑似混淆载荷)")

        # 凭证读取的其他渠道
        if re.search(r"\b(?:clipboard|readText)\b", low) and net:
            v.severity = _raise(Severity.HIGH, v.severity)
            v.reasons.append(f"[{label}] 读取剪贴板并外传")

        # 明显的高危字符串目标
        if "javascript:" in low or "vbscript:" in low:
            v.severity = _raise(Severity.MEDIUM, v.severity)
            v.reasons.append(f"[{label}] 使用 javascript:/vbscript: 伪协议")

        # 网络存在但仅白名单主机 → 低风险(图表库取数)
        if net and not any(f.startswith("[") for f in []) and v.severity < Severity.MEDIUM:
            v.severity = _raise(Severity.LOW, v.severity)
            if not v.reasons:
                v.reasons.append(f"[{label}] 存在网络调用(目标均在白名单内)")

    # -- 折叠与解码 -------------------------------------------------------
    def _fold(self, tokens: List[jslex.Token]) -> "_Folded":
        """常量折叠:相邻字符串相加、模板静态拼接。"""
        out: List[jslex.Token] = []
        changed = False
        i = 0
        n = len(tokens)
        while i < n:
            t = tokens[i]
            if t.kind in ("string", "template") and i + 2 < n + 0 and i + 1 < n:
                # 收集 a + b + c ...
                parts = [t]
                j = i + 1
                while j + 1 < n and tokens[j].is_punct("+") and tokens[j + 1].kind in ("string", "template"):
                    parts.append(tokens[j + 1])
                    j += 2
                if len(parts) > 1:
                    joined = "".join(_tok_static_text(p) for p in parts)
                    out.append(
                        jslex.Token(
                            "string", joined, t.start, parts[-1].end,
                            joined, synthetic=True,
                        )
                    )
                    changed = True
                    i = j
                    continue
            out.append(t)
            i += 1
        text = " ".join(
            (t.value if t.kind in ("string", "ident", "keyword", "number", "punct", "regex") else (t.raw or ""))
            for t in out
        )
        return _Folded(out, text, changed)

    def _decode_literals(self, tokens: List[jslex.Token]) -> List[str]:
        """解码 atob('...') 与 String.fromCharCode(...) 的字面量参数。"""
        results: List[str] = []
        n = len(tokens)
        for i, t in enumerate(tokens):
            if t.kind != "ident":
                continue
            name = t.value
            # atob / unescape / decodeURIComponent
            if name in DECODER_FUNCS - {"fromCharCode"}:
                if i + 3 < n and tokens[i + 1].is_punct("(") and tokens[i + 2].kind == "string":
                    arg = tokens[i + 2].value
                    dec = _decode_arg(name, arg)
                    if dec:
                        results.append(dec)
                        continue
            # String.fromCharCode(...) 或 fromCharCode(...)
            if name == "fromCharCode" or (name == "String" and i + 3 < n and tokens[i + 1].is_punct(".") and tokens[i + 2].is_ident("fromCharCode")):
                k = i + 2 if name == "String" else i
                if k + 2 < n and tokens[k + 1].is_punct("("):
                    args: List[int] = []
                    j = k + 2
                    ok = True
                    while j < n and not tokens[j].is_punct(")"):
                        if tokens[j].kind == "number":
                            try:
                                args.append(int(float(tokens[j].value.rstrip("n").replace("_", ""))))
                            except ValueError:
                                ok = False
                                break
                        elif tokens[j].kind == "punct" and tokens[j].value == ",":
                            pass
                        elif tokens[j].kind == "string":
                            for ch in tokens[j].value:
                                args.append(ord(ch))
                        else:
                            ok = False
                            break
                        j += 1
                    if ok and args:
                        try:
                            s = "".join(chr(a) for a in args if 0 <= a <= 0x10FFFF)
                        except (ValueError, OverflowError):
                            s = ""
                        if s:
                            results.append(s)
        return results

    # -- 结构特征 ---------------------------------------------------------
    def _feature_signals(self, code: str, tokens: List[jslex.Token], v: JsVerdict) -> None:
        # 计算成员访问 document["cookie"] 已由字符串扫描覆盖;这里检测整体可疑度
        if len(tokens) > 200_000:
            v.obfuscated = True
            v.reasons.append("脚本 token 数量异常")
            v.severity = _raise(Severity.MEDIUM, v.severity)
        if patterns.has_bidi_controls(code):
            v.obfuscated = True
            v.severity = _raise(Severity.HIGH, v.severity)
            v.reasons.append("脚本含双向文本控制字符(隐藏代码)")
        # 远程脚本加载(createElement('script') / importScripts 等)
        for m in re.finditer(r"""<script[^>]+src\s*=\s*["']?([^"'\s>]+)""", code, re.I):
            info = patterns.classify_url(m.group(1))
            if info.scheme in ("http", "https"):
                v.remote_hosts.add(info.host)
                if not patterns.host_allowed(info.host, self.policy.script_hosts):
                    v.severity = _raise(Severity.HIGH, v.severity)
                    v.reasons.append(f"加载非白名单远程脚本: {info.host}")


@dataclass
class _Folded:
    tokens: List[jslex.Token]
    text: str
    changed: bool


def _tok_static_text(t: jslex.Token) -> str:
    if t.kind == "template":
        # 仅当模板没有动态表达式时才是静态的
        if t.exprs:
            return t.raw or ""
        return "".join(t.quasis or [])
    return t.value


def _decode_arg(name: str, arg: str) -> Optional[str]:
    try:
        if name == "atob":
            t = arg.replace("-", "+").replace("_", "/")
            t += "=" * (-len(t) % 4)
            try:
                return base64.b64decode(t, validate=False).decode("utf-8")
            except (binascii.Error, ValueError, UnicodeDecodeError):
                return None
        if name in ("unescape", "decodeURIComponent", "decodeURI"):
            from urllib.parse import unquote
            if name == "unescape":
                from urllib.parse import unquote as _uq
                return _uq(arg)
            return unquote(arg)
    except Exception:
        return None
    return None


_URLS_RE = re.compile(
    r"""(?:https?|wss?|ftp)://[^\s"'`<>\\()]+""", re.I
)


def script_srcs(html: str) -> List[str]:
    return [m.group(1) for m in re.finditer(r"""<script\b[^>]*\bsrc\s*=\s*["']?([^"'\s>]+)""", html, re.I)]


def remote_script_hosts(html: str, policy: Policy) -> Tuple[Set[str], Set[str]]:
    """返回 (允许的远程主机, 不允许的远程主机)。"""
    ok: Set[str] = set()
    bad: Set[str] = set()
    for src in script_srcs(html):
        info = patterns.classify_url(src)
        if info.scheme in ("http", "https"):
            (ok if patterns.host_allowed(info.host, policy.script_hosts) else bad).add(info.host)
        elif info.scheme not in ("", "data", "blob"):
            bad.add(f"{info.scheme}:")
    return ok, bad
