"""Markdown 与 LaTeX 中的活动内容处理。

Markdown 单元格本身通常不执行,但渲染器允许内嵌 HTML(``<script>``、
``<img onerror>``、``![x](javascript:...)``),所以对原始 HTML 片段与
危险链接做处理。LaTeX 输出(MathJax)里的 ``\\href{javascript:...}``、
``\\htmlClass`` 等也可能触发动作,按策略剥离或标记。
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from . import patterns
from .jsanalyze import JsAnalyzer
from .model import Action, Finding, Severity
from .policy import Policy


def _host_from_url(u: str) -> Optional[str]:
    info = patterns.classify_url(u)
    if info.scheme in ("http", "https"):
        return info.host
    return None


_MD_TAG_RE = re.compile(r"<\s*(/?)\s*([a-zA-Z][a-zA-Z0-9-]*)", re.I)


def sanitize_markdown(
    text: str, policy: Policy, analyzer: JsAnalyzer, location: str
) -> Tuple[str, List[Finding]]:
    if not text:
        return text, []
    findings: List[Finding] = []

    def add(rule: str, sev: Severity, act: Action, msg: str, ev: str = "") -> None:
        findings.append(Finding(rule, sev, act, location, msg, ev or text[:120]))

    if policy.markdown_mode == "keep":
        # 仅报告
        for tok in patterns.scan_text_for_active(text):
            add("markdown-active", Severity.MEDIUM, Action.FLAGGED,
                f"Markdown 含活动内容特征 {tok!r}")
        return text, findings

    changed = False

    # 1) 危险协议链接 / 图片
    def _link(m: "re.Match[str]") -> str:
        nonlocal changed
        url = m.group(2).strip()
        info = patterns.classify_url(url)
        if info.scheme in ("javascript", "vbscript", "livescript"):
            changed = True
            add("markdown-active-link", Severity.CRITICAL, Action.STRIPPED,
                "移除活动协议链接", url[:120])
            return m.group(1) + "#"
        if info.scheme == "data" and not re.match(r"(?i)data:image/(png|jpe?g|gif|webp)", url):
            changed = True
            add("markdown-data-link", Severity.HIGH, Action.STRIPPED,
                "移除非图片 data: 链接", url[:120])
            return m.group(1) + "#"
        return m.group(0)

    before = text
    text = re.sub(r"(!?\[[^\]]*\]\()\s*([^)\s]+)\s*(\)|\s+\"[^\"]*\")", _link, text)
    if text != before:
        changed = True

    # 2) 内嵌 HTML:对整段 HTML 片段走 HTML 净化器
    if re.search(r"<\s*[a-zA-Z!/]", text):
        before = text
        text, html_findings = _sanitize_markdown_html(text, policy, analyzer, location)
        findings.extend(html_findings)
        if text != before:
            changed = True

    # 3) 删除危险的 HTML 注释式隐藏
    text2 = re.sub(r"<!--.*?-->", "", text, flags=re.S) if policy.strip_comments else text
    if text2 != text:
        changed = True
        text = text2

    if changed:
        findings.append(Finding("markdown-sanitized", Severity.LOW, Action.REWRITTEN,
                                location, "Markdown 已被净化"))
    return text, findings


def _sanitize_markdown_html(
    text: str, policy: Policy, analyzer: JsAnalyzer, location: str
) -> Tuple[str, List[Finding]]:
    """净化 Markdown 中内嵌的 HTML 片段,保留 Markdown 语法。

    做法:按 Markdown 结构粗分块,只把"看起来是 HTML 的连续行"交给
    HTML 净化器,其余文本(标题、列表、代码块)原样保留。
    """
    from .htmlsanitizer import sanitize_html

    lines = text.split("\n")
    out: List[str] = []
    findings: List[Finding] = []
    buf: List[str] = []
    in_fence = False

    def flush() -> None:
        nonlocal buf
        if not buf:
            return
        block = "\n".join(buf)
        buf = []
        if patterns.is_probably_html(block) and "<" in block:
            r = sanitize_html(block, policy, analyzer, location, max_iterations=2)
            findings.extend(r.findings)
            out.append(r.html)
        else:
            out.append(block)

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            flush()
            out.append(line)
            continue
        if in_fence:
            out.append(line)
            continue
        if "<" in line and re.search(r"<\s*/?\s*[a-zA-Z!]", line):
            buf.append(line)
        else:
            flush()
            out.append(line)
    flush()
    return "\n".join(out), findings


# --- LaTeX ---------------------------------------------------------------

_LATEX_ACTIVE_RE = re.compile(
    r"\\(?:href|url|htmlClass|htmlStyle|htmlId|htmlData|includegraphics|"
    r"class|style|require|hspace\*?|vspace\*?)\s*\{",
    re.I,
)
_LATEX_JAVASCRIPT_RE = re.compile(r"\\(?:href|url)\s*\{\s*(?:javascript|vbscript|data)\s*:", re.I)
# 命中活动协议时,替换整个 \href{...} 的参数(可能含嵌套花括号)
_LATEX_ACTIVE_HREF_FULL = re.compile(
    r"\\(?:href|url)\s*\{\s*(?:javascript|vbscript|data)\s*:(?:[^{}]|\{[^{}]*\})*\}",
    re.I,
)


def sanitize_latex(
    text: str, policy: Policy, location: str
) -> Tuple[str, List[Finding]]:
    if not text:
        return text, []
    findings: List[Finding] = []
    if policy.latex_mode == "keep":
        if _LATEX_JAVASCRIPT_RE.search(text):
            findings.append(Finding("latex-active-link", Severity.HIGH, Action.FLAGGED,
                                    location, "LaTeX 含活动协议链接"))
        return text, findings

    changed = False
    if _LATEX_JAVASCRIPT_RE.search(text):
        findings.append(Finding("latex-active-link", Severity.CRITICAL, Action.STRIPPED,
                                location, "移除 LaTeX 活动协议链接", text[:120]))
        text = _LATEX_ACTIVE_HREF_FULL.sub(r"\\href{about:blank}", text)
        changed = True

    if policy.latex_mode == "strip":
        # 移除可触发宏/资源的构造
        if _LATEX_ACTIVE_RE.search(text):
            findings.append(Finding("latex-active-macro", Severity.MEDIUM, Action.STRIPPED,
                                    location, "移除 LaTeX 活动宏 \\href/\\class/\\html* 等",
                                    text[:120]))
            text = re.sub(
                r"\\(?:href|url|includegraphics|class|style|htmlClass|htmlStyle|"
                r"htmlId|htmlData|require)\s*\{[^{}]*\}",
                "",
                text,
                flags=re.I,
            )
            text = re.sub(r"\\hspace\*?\s*\{[^{}]*\}", "", text, flags=re.I)
            text = re.sub(r"\\vspace\*?\s*\{[^{}]*\}", "", text, flags=re.I)
            changed = True
    else:  # sanitize
        # 只剥离明显危险的外部引用,保留公式
        if _LATEX_ACTIVE_RE.search(text):
            findings.append(Finding("latex-active-macro", Severity.LOW, Action.FLAGGED,
                                    location, "LaTeX 含可加载资源的宏,请人工确认",
                                    text[:120]))
    return text, findings
