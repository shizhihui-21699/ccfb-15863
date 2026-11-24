"""HTML/SVG 净化:在保留正常图表的同时清除可执行内容。

为什么不用正则:HTML 解析有大量怪癖(实体、原始文本元素、畸形标签),
正则清理极易被绕过并产生 mXSS。这里用标准库 ``html.parser`` 做词法级
重建,并对输出做定点迭代(重复净化直到稳定),消除"净化后再解析又变成
活动内容"的变异型 XSS。

保留策略:
* matplotlib 的静态 SVG / HTML 表格 / Styler → 完整保留(本来就是静态标记)。
* plotly / bokeh / altair 的内联 ``<script>`` → 交给 :mod:`jsanalyze` 判定,
  安全则保留,危险则整段移除。
* 远程脚本仅允许白名单 CDN,且强制 https。
* iframe/object/embed/form/base/meta-refresh 默认移除。
* 注入 CSP ``<meta>`` 作为纵深防御。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import List, Optional, Set, Tuple

from . import patterns
from .jsanalyze import JsAnalyzer, JsVerdict
from .model import Action, Finding, Severity
from .policy import Policy

# 内容连同标签一起丢弃的元素
DROP_WITH_CONTENT = {
    "object", "embed", "applet", "base", "frame", "frameset", "portal",
    "plaintext", "xmp", "noembed", "noframes", "noscript",
    "template",  # 模板内容会被某些库当字符串取出再注入,直接丢弃更安全
}
# 仅丢弃标签本身(内容保留为文本)
DROP_TAG_ONLY = {"html", "head", "body", "title"}
# 表单类:可被用于凭据收集
DROP_FORM = {"form", "input", "button", "select", "option", "textarea", "keygen", "datalist", "output"}

VOID_ELEMENTS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
    "meta", "param", "source", "track", "wbr",
}
RAW_TEXT_ELEMENTS = {"script", "style"}

# 可执行脚本的 MIME 类型;其余 type 视为惰性数据(如 application/json)
EXECUTABLE_SCRIPT_TYPES = {
    "", "module", "text/javascript", "application/javascript", "text/ecmascript",
    "application/ecmascript", "text/jscript", "text/livescript",
    "application/x-javascript", "application/x-ecmascript", "text/javascript1.0",
    "text/javascript1.1", "text/javascript1.2", "text/javascript1.3",
    "text/javascript1.4", "text/javascript1.5", "text/x-javascript",
    "text/x-ecmascript",
}

URL_ATTRS = {
    "href", "xlink:href", "src", "action", "formaction", "poster",
    "background", "dynsrc", "lowsrc", "manifest", "data", "codebase",
    "cite", "longdesc", "usemap", "profile", "archive", "classid",
    "srcset", "imagesrcset",
}
ALWAYS_DROP_ATTRS = {"ping", "srcdoc", "nonce", "integrity"}
SAFE_DATA_IMG_PREFIX = ("data:image/", "data:font/", "data:application/font")
CSS_ACTIVE_RE = re.compile(
    r"(?:expression\s*\(|javascript\s*:|vbscript\s*:|-moz-binding|behavior\s*:|"
    r"@import\b|@namespace\b|\\\\|\*\s*/\s*\*|url\s*\(\s*['\"]?\s*(?:https?:)?//)",
    re.I,
)

_CSS_ESCAPE_RE = re.compile(r"\\([0-9a-fA-F]{1,6}\s?|.)", re.S)


def css_unescape(s: str) -> str:
    def _r(m: "re.Match[str]") -> str:
        g = m.group(1)
        hx = g.strip()
        if hx and all(c in "0123456789abcdefABCDEF" for c in hx):
            try:
                return chr(int(hx, 16))
            except (ValueError, OverflowError):
                return ""
        return g

    return _CSS_ESCAPE_RE.sub(_r, s)


def _esc_text(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _esc_attr(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


@dataclass
class HtmlResult:
    html: str
    findings: List[Finding] = field(default_factory=list)
    kept_scripts: int = 0
    stripped_scripts: int = 0
    changed: bool = False


class _Rewriter(HTMLParser):
    def __init__(self, policy: Policy, analyzer: JsAnalyzer, location: str,
                 max_depth: int = 512) -> None:
        super().__init__(convert_charrefs=True)
        self.policy = policy
        self.analyzer = analyzer
        self.location = location
        self.max_depth = max_depth
        self.out: List[str] = []
        self.stack: List[str] = []
        self.findings: List[Finding] = []
        self.kept_scripts = 0
        self.stripped_scripts = 0
        self.changed = False
        self.too_deep = False
        # 跳过(含内容)元素的状态
        self.skip_tag: Optional[str] = None
        self.skip_depth = 0
        # 原始文本缓冲
        self.raw_tag: Optional[str] = None
        self.raw_attrs: List[Tuple[str, Optional[str]]] = []
        self.raw_buf: List[str] = []

    # -- 工具 -------------------------------------------------------------
    def _add(self, rule: str, sev: Severity, action: Action, msg: str, ev: str = "") -> None:
        self.findings.append(Finding(rule, sev, action, self.location, msg, ev))

    def _tag(self, name: str, attrs: List[Tuple[str, Optional[str]]], selfclose: bool) -> str:
        parts = [name]
        for k, v in attrs:
            if v is None:
                parts.append(k)
            else:
                parts.append(f'{k}="{_esc_attr(v)}"')
        body = " ".join(parts)
        return f"<{body} />" if selfclose else f"<{body}>"

    # -- 属性处理 ---------------------------------------------------------
    def _clean_attrs(
        self, tag: str, attrs: List[Tuple[str, Optional[str]]]
    ) -> List[Tuple[str, Optional[str]]]:
        out: List[Tuple[str, Optional[str]]] = []
        seen: Set[str] = set()
        for k, v in attrs:
            kl = k.lower()
            if kl in seen:  # 重复属性:保留第一个
                self.changed = True
                continue
            seen.add(kl)
            if not re.fullmatch(r"[A-Za-z_:][-A-Za-z0-9_:.]*", k or ""):
                self.changed = True
                continue
            if kl.startswith("on"):
                self.changed = True
                self._handle_event_attr(k, v)
                if self.policy.allow_inline_events:
                    out.append((k, v))
                continue
            if kl in ALWAYS_DROP_ATTRS:
                self.changed = True
                self._add("html-dangerous-attr", Severity.HIGH, Action.STRIPPED,
                          f"移除危险属性 {k}", (v or "")[:120])
                continue
            # 任意属性值里的活动协议(SVG 的 values/from/to、xlink 等)
            if v is not None and kl not in URL_ATTRS and re.search(
                r"(?:javascript|vbscript|livescript)\s*:", v, re.I
            ):
                self.changed = True
                self._add("html-active-attr-value", Severity.HIGH, Action.STRIPPED,
                          f"移除含活动协议的属性 {k}", v[:120])
                continue
            if kl == "style" and v:
                nv = self._clean_css(v, "style 属性")
                if nv != v:
                    self.changed = True
                if nv.strip():
                    out.append((k, nv))
                continue
            if kl in URL_ATTRS and v is not None:
                nv = self._clean_url_attr(kl, v)
                if nv is None:
                    self.changed = True
                    continue
                if nv != v:
                    self.changed = True
                out.append((k, nv))
                continue
            if kl == "type" and tag in ("script", "style", "link"):
                out.append((k, (v or "").strip().lower()))
                continue
            out.append((k, v))
        return out

    def _handle_event_attr(self, name: str, value: Optional[str]) -> None:
        """事件处理器天然是活动内容:分析其代码体以定级,再移除。"""
        body = value or ""
        verdict = self.analyzer.analyze(body) if body.strip() else None
        sev = Severity.HIGH
        detail = "内联事件处理器本身即可执行任意脚本"
        if verdict is not None and verdict.severity > sev:
            sev = verdict.severity
            detail = verdict.summary()
        self._add("html-event-handler", sev, Action.STRIPPED,
                  f"移除内联事件处理器 {name}({detail})", body[:160])

    def _clean_url_attr(self, name: str, value: str) -> Optional[str]:
        raw = value.strip()
        info = patterns.classify_url(raw)
        if name == "srcset" or name == "imagesrcset":
            return self._clean_srcset(raw)
        if info.scheme in ("javascript", "vbscript", "livescript"):
            self._add("html-active-url", Severity.CRITICAL, Action.STRIPPED,
                      f"移除活动协议 URL({name})", raw[:160])
            return None
        if info.scheme == "data":
            low = raw.lower()
            if any(low.startswith(p) for p in SAFE_DATA_IMG_PREFIX):
                return raw
            if low.startswith("data:image/svg+xml"):
                # SVG data URI 可含脚本;解码后检查
                self._add("html-svg-data-uri", Severity.MEDIUM, Action.FLAGGED,
                          "内联 SVG data URI,请确认内容", raw[:80])
                return raw
            self._add("html-active-url", Severity.HIGH, Action.STRIPPED,
                      f"移除非图片 data: URL({name})", raw[:120])
            return None
        if info.scheme in ("http", "https") and info.host:
            if info.scheme == "http":
                self.changed = True
                raw = "https://" + raw.split("://", 1)[1]
            if name in ("href", "xlink:href", "src", "data", "poster", "background"):
                if not patterns.host_allowed(info.host, self.policy.data_hosts):
                    self._add("html-remote-resource", Severity.LOW, Action.FLAGGED,
                              f"引用外部主机资源({name}): {info.host}", raw[:160])
            return raw
        if info.scheme in ("ftp", "file", "blob", "filesystem", "ws", "wss"):
            self._add("html-unusual-url", Severity.MEDIUM, Action.STRIPPED,
                      f"移除非常规协议 URL({name}): {info.scheme}", raw[:120])
            return None
        return raw

    def _clean_srcset(self, value: str) -> str:
        keep: List[str] = []
        for part in value.split(","):
            bits = part.strip().split()
            if not bits:
                continue
            url = bits[0]
            info = patterns.classify_url(url)
            if info.scheme in ("javascript", "vbscript", "livescript"):
                self._add("html-active-url", Severity.HIGH, Action.STRIPPED,
                          "移除 srcset 中的活动 URL", url[:120])
                continue
            keep.append(" ".join(bits))
        return ", ".join(keep)

    # -- CSS --------------------------------------------------------------
    def _clean_css(self, css: str, where: str) -> str:
        if not self.policy.sanitize_css or not css:
            return css
        changed = False
        norm = css_unescape(css)
        if norm != css:
            changed = True
        low = norm.lower()
        # 删除危险构造
        if "expression" in low or "javascript:" in low or "-moz-binding" in low or "behavior" in low:
            self._add("css-active-content", Severity.HIGH, Action.REWRITTEN,
                      f"{where} 含危险 CSS 构造(已清除)", norm[:160])
            norm = re.sub(r"expression\s*\(", "blocked(", norm, flags=re.I)
            norm = re.sub(r"(?:javascript|vbscript)\s*:", "blocked:", norm, flags=re.I)
            norm = re.sub(r"-moz-binding\s*:[^;}]*", "", norm, flags=re.I)
            norm = re.sub(r"(?:^|[;{])\s*behavior\s*:[^;}]*", "", norm, flags=re.I)
            changed = True
        if "@import" in low or "@namespace" in low:
            self._add("css-import", Severity.MEDIUM, Action.REWRITTEN,
                      f"{where} 含 @import/@namespace(已清除)", norm[:160])
            norm = re.sub(r"@import[^;]*;?", "", norm, flags=re.I)
            norm = re.sub(r"@namespace[^;]*;?", "", norm, flags=re.I)
            changed = True
        # url(...) 只允许 data: 与白名单 https
        def _url(m: "re.Match[str]") -> str:
            nonlocal changed
            q = m.group(1)
            u = m.group(2).strip()
            info = patterns.classify_url(u)
            if info.scheme in ("javascript", "vbscript"):
                changed = True
                return "url(about:blank)"
            if info.scheme in ("http", "https") and info.host:
                if not patterns.host_allowed(info.host, self.policy.data_hosts):
                    changed = True
                    # 外部资源可用于追踪像素(泄露阅读即打开),非白名单则阻断
                    self._add("css-remote-url", Severity.MEDIUM, Action.REWRITTEN,
                              f"{where} 引用非白名单外部资源(已阻断): {info.host}", u[:120])
                    return "url(about:blank)"
            elif info.scheme not in ("data", "blob", ""):
                changed = True
                return "url(about:blank)"
            return m.group(0)

        norm2 = re.sub(r"""url\s*\(\s*(['"]?)(.*?)\1\s*\)""", _url, norm, flags=re.I | re.S)
        if norm2 != norm:
            changed = True
        if "\\" in norm2:  # 残留 CSS 转义序列本身可疑
            changed = True
            norm2 = css_unescape(norm2)
        if changed:
            self.changed = True
        return norm2

    # -- 解析回调 ---------------------------------------------------------
    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        tag = tag.lower()
        if self.skip_tag is not None:
            if tag == self.skip_tag:
                self.skip_depth += 1
            return
        if self.too_deep:
            return

        if tag in DROP_WITH_CONTENT:
            self._drop_element(tag, attrs)
            return
        if tag in SVG_ACTIVE_ELEMENTS:
            # SVG 动画/事件元素可把 href 改写为 javascript: 或触发回调
            self._add("svg-active-element", Severity.HIGH, Action.STRIPPED,
                      f"移除 SVG 活动元素 <{tag}>")
            self.changed = True
            self.skip_tag = tag
            self.skip_depth = 1
            return
        if tag in DROP_FORM:
            self._add("html-form", Severity.MEDIUM, Action.STRIPPED,
                      f"移除表单类元素 <{tag}>(可用于凭据收集)")
            self.changed = True
            return
        if tag in DROP_TAG_ONLY:
            self._handle_tag_only(tag, attrs)
            return

        if tag == "meta":
            self._handle_meta(attrs)
            return
        if tag == "link":
            self._handle_link(attrs)
            return
        if tag == "iframe":
            self._handle_iframe(attrs)
            return
        if tag in ("script", "style"):
            # 进入原始文本模式
            self.raw_tag = tag
            self.raw_attrs = attrs
            self.raw_buf = []
            return

        if len(self.stack) >= self.max_depth:
            self.too_deep = True
            self._add("html-too-deep", Severity.HIGH, Action.REPLACED,
                      "HTML 嵌套过深,已整体替换")
            return

        clean = self._clean_attrs(tag, attrs)
        if clean != attrs:
            self.changed = True
        self.out.append(self._tag(tag, clean, False))
        self.stack.append(tag)

    def handle_startendtag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        tag = tag.lower()
        if self.skip_tag is not None:
            return
        if tag in DROP_WITH_CONTENT or tag in DROP_FORM:
            self.changed = True
            sev = Severity.CRITICAL if tag in ("object", "embed", "applet") else Severity.HIGH
            self._add("html-stripped-element", sev, Action.STRIPPED,
                      f"移除元素 <{tag}>")
            return
        if tag in SVG_ACTIVE_ELEMENTS:
            self.changed = True
            self._add("svg-active-element", Severity.HIGH, Action.STRIPPED,
                      f"移除 SVG 活动元素 <{tag}>")
            return
        if tag in DROP_TAG_ONLY:
            return
        # 自闭合形式也要走相同策略,否则 <link/>、<meta/> 会绕过检查
        if tag == "meta":
            self._handle_meta(attrs)
            return
        if tag == "link":
            self._handle_link(attrs)
            return
        if tag == "iframe":
            self._handle_iframe(attrs)
            return
        if tag in ("script", "style"):
            # 自闭合 script/style 无内容;按空内容走同一处理
            self._handle_empty_raw(tag, attrs)
            return
        clean = self._clean_attrs(tag, attrs)
        if clean != attrs:
            self.changed = True
        if tag in VOID_ELEMENTS:
            self.out.append(self._tag(tag, clean, False))
        else:
            self.out.append(self._tag(tag, clean, True))

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if self.skip_tag is not None:
            if tag == self.skip_tag:
                self.skip_depth -= 1
                if self.skip_depth <= 0:
                    self.skip_tag = None
            return
        if self.raw_tag is not None:
            if tag == self.raw_tag:
                self.finish_raw()
            return
        if tag in VOID_ELEMENTS or tag in DROP_WITH_CONTENT or tag in DROP_FORM:
            return
        if tag in DROP_TAG_ONLY:
            return
        if tag in VOID_ELEMENTS:
            self.out.append(self._tag(tag, clean, False))
            return
        if tag in self.stack:
            # 关闭到该标签(容忍畸形嵌套)
            while self.stack:
                top = self.stack.pop()
                self.out.append(f"</{top}>")
                if top == tag:
                    break
        elif tag == "script" or tag == "style":
            return

    def handle_data(self, data: str) -> None:
        if self.skip_tag is not None:
            return
        if self.raw_tag is not None:
            self.raw_buf.append(data)
            return
        if not data:
            return
        self.out.append(_esc_text(data))

    def handle_comment(self, data: str) -> None:
        if self.skip_tag is not None:
            return
        if self.policy.strip_comments:
            self.changed = True
            return
        # 注释里若含条件编译/脚本,丢弃
        if "[" in data and re.search(r"<\s*script|\[if\s|\[endif", data, re.I):
            self._add("html-comment-active", Severity.MEDIUM, Action.STRIPPED,
                      "移除含活动内容的注释", data[:120])
            self.changed = True
            return
        self.out.append(f"<!--{_esc_text(data)}-->")

    def handle_decl(self, decl: str) -> None:
        # 丢弃 DOCTYPE 等声明(片段输出无需)
        self.changed = True

    def handle_pi(self, data: str) -> None:
        self.changed = True

    def handle_entityref(self, name: str) -> None:  # convert_charrefs 下不触发
        self.out.append(_esc_text(f"&{name};"))

    def handle_charref(self, name: str) -> None:
        self.out.append(_esc_text(f"&#{name};"))

    # -- 具体元素 ---------------------------------------------------------
    def _drop_element(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        sev = Severity.CRITICAL if tag in ("object", "embed", "applet") else Severity.HIGH
        self._add("html-blocked-element", sev, Action.STRIPPED,
                  f"移除 <{tag}> 元素(可执行/可嵌入内容)")
        self.changed = True
        if tag in VOID_ELEMENTS:
            return
        self.skip_tag = tag
        self.skip_depth = 1

    def _handle_tag_only(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag in ("html", "head", "body", "title"):
            # 仅去掉包裹标签,内容保留
            self.changed = True
            return
        self.changed = True
        return

    def _handle_meta(self, attrs: List[Tuple[str, Optional[str]]]) -> None:
        d = {k.lower(): (v or "") for k, v in attrs}
        if "http-equiv" in d:
            eq = d["http-equiv"].strip().lower()
            # 允许我们自己的 CSP 声明(净化幂等的前提)
            if eq == "content-security-policy" and _is_own_csp(d.get("content", "")):
                self.out.append(self._tag("meta", self._clean_attrs("meta", attrs), False))
                return
            self._add("html-meta-http-equiv", Severity.HIGH, Action.STRIPPED,
                      f"移除 http-equiv={eq} 的 meta", d.get("content", "")[:120])
            self.changed = True
            return
        # 仅保留 charset / viewport / name=... 的普通 meta
        self.out.append(self._tag("meta", self._clean_attrs("meta", attrs), False))

    def _handle_link(self, attrs: List[Tuple[str, Optional[str]]]) -> None:
        d = {k.lower(): (v or "") for k, v in attrs}
        rel = d.get("rel", "").strip().lower()
        href = d.get("href", "").strip()
        info = patterns.classify_url(href)
        if rel in ("stylesheet", "preload", "prefetch", "modulepreload", "import"):
            if info.scheme in ("http", "https") and patterns.host_allowed(info.host, self.policy.script_hosts):
                self.out.append(self._tag("link", self._clean_attrs("link", attrs), False))
                return
            self._add("html-remote-stylesheet", Severity.HIGH, Action.STRIPPED,
                      f"移除非白名单外部样式/预加载: {rel}", href[:160])
            self.changed = True
            return
        self._add("html-link-element", Severity.LOW, Action.STRIPPED,
                  f"移除 link(rel={rel})", href[:120])
        self.changed = True

    def _handle_iframe(self, attrs: List[Tuple[str, Optional[str]]]) -> None:
        d = {k.lower(): (v or "") for k, v in attrs}
        if not self.policy.allow_iframes:
            self._add("html-iframe", Severity.HIGH, Action.STRIPPED,
                      "移除 iframe(可加载任意页面)")
            self.changed = True
            if "srcdoc" in d:
                pass
            return
        # 保留但强制 sandbox,去掉 srcdoc 里的脚本风险由 sandbox 兜底
        clean: List[Tuple[str, Optional[str]]] = []
        for k, v in attrs:
            kl = k.lower()
            if kl in ("sandbox", "srcdoc", "allow", "allowfullscreen"):
                continue
            clean.append((k, v))
        clean.append(("sandbox", self.policy.iframe_sandbox))
        info = patterns.classify_url(d.get("src", ""))
        if info.scheme in ("http", "https") and not patterns.host_allowed(
            info.host, self.policy.data_hosts
        ):
            self._add("html-iframe-external", Severity.MEDIUM, Action.REWRITTEN,
                      f"iframe 指向外部主机: {info.host}(已加 sandbox)", d.get("src", "")[:160])
        else:
            self._add("html-iframe", Severity.MEDIUM, Action.REWRITTEN,
                      f"iframe 已加 sandbox={self.policy.iframe_sandbox!r}", d.get("src", "")[:120])
        self.changed = True
        self.out.append(self._tag("iframe", clean, False))
        # iframe 内部内容不是合法 iframe 子内容;按原始文本丢弃直到 </iframe>,
        # 既避免把标签当正文转义(破坏幂等),也消除解析器分歧风险。
        self.skip_tag = "iframe"
        self.skip_depth = 1

    # -- 原始文本收尾 -----------------------------------------------------
    def finish_raw(self) -> None:
        if self.raw_tag is None:
            return
        tag = self.raw_tag
        text = "".join(self.raw_buf)
        attrs = self.raw_attrs
        self.raw_tag = None
        self.raw_attrs = []
        self.raw_buf = []

        if tag == "style":
            if not self.policy.keep_only_static:
                css = self._clean_css(text, "样式块")
                self.out.append(f"<style>{css}</style>")
            else:
                self.changed = True
                self._add("css-block-stripped", Severity.LOW, Action.STRIPPED,
                          "strict 策略移除了样式块")
            return

        # tag == script
        self._handle_script(attrs, text)

    def _handle_empty_raw(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        """处理无内容的自闭合 <script/> 或 <style/>。"""
        if tag == "style":
            if not self.policy.keep_only_static:
                self.out.append("<style></style>")
            return
        self._handle_script(attrs, "")

    def _handle_script(self, attrs: List[Tuple[str, Optional[str]]], text: str) -> None:
        d = {k.lower(): (v or "") for k, v in attrs}
        stype = d.get("type", "").strip().lower()
        # 去掉 charset 参数
        stype = stype.split(";")[0].strip()
        src = d.get("src", "").strip()

        # 惰性数据脚本(application/json / application/ld+json / text/template 等)
        if stype and stype not in EXECUTABLE_SCRIPT_TYPES:
            if patterns.SCRIPT_TAG_RE.search(text) or "<script" in text.lower():
                # 数据块里不能出现脚本标签
                self._add("script-data-active", Severity.HIGH, Action.REWRITTEN,
                          f"<script type={stype}> 数据块含脚本标签,已转义", text[:120])
                text = re.sub(r"<\s*(/?)\s*script", r"&lt;\1script", text, flags=re.I)
                self.changed = True
            self.kept_scripts += 1
            self.out.append(self._tag("script", [("type", stype)], False) if stype else "<script>")
            self.out.append(text)
            self.out.append("</script>")
            return

        # 远程脚本
        if src:
            info = patterns.classify_url(src)
            if info.scheme in ("javascript", "vbscript"):
                self._add("script-active-src", Severity.CRITICAL, Action.STRIPPED,
                          "移除活动协议脚本 src", src[:160])
                self.stripped_scripts += 1
                self.changed = True
                return
            if info.scheme in ("http", "https"):
                if not self.policy.allow_remote_scripts or not patterns.host_allowed(
                    info.host, self.policy.script_hosts
                ):
                    self._add("script-remote-blocked", Severity.HIGH, Action.STRIPPED,
                              f"阻止加载非白名单远程脚本: {info.host or src}", src[:160])
                    self.stripped_scripts += 1
                    self.changed = True
                    return
                if info.scheme == "http":
                    src = "https://" + src.split("://", 1)[1]
                    self.changed = True
                verdict = self.analyzer.analyze(src)
                self.kept_scripts += 1
                self._record_verdict("远程脚本", src, verdict, Action.FLAGGED)
                clean = [(k, v) for (k, v) in attrs if k.lower() != "src"]
                clean.append(("src", src))
                self.out.append(self._tag("script", clean, False))
                if text.strip():
                    self.out.append(text)
                self.out.append("</script>")
                return
            if info.scheme == "data":
                self._add("script-data-src", Severity.HIGH, Action.STRIPPED,
                          "移除 data: 脚本 src", src[:120])
                self.stripped_scripts += 1
                self.changed = True
                return
            # 相对路径:无法判定,保留为相对引用(同源)
            self.kept_scripts += 1
            clean = self._clean_attrs("script", attrs)
            self.out.append(self._tag("script", clean, False))
            if text.strip():
                self.out.append(text)
            self.out.append("</script>")
            return

        # 内联脚本
        if not text.strip():
            return
        verdict = self.analyzer.analyze(text)

        if self.policy.script_mode == "strip" or self.policy.keep_only_static:
            self.stripped_scripts += 1
            self.changed = True
            self._record_verdict("内联脚本", text, verdict, Action.STRIPPED)
            self._add("script-stripped", Severity.LOW, Action.STRIPPED,
                      "策略要求移除内联脚本")
            return

        if self.policy.script_mode == "keep_all":
            self.kept_scripts += 1
            self._record_verdict("内联脚本", text, verdict, Action.FLAGGED)
            clean = self._clean_attrs("script", attrs)
            self.out.append(self._tag("script", clean, False))
            self.out.append(text)
            self.out.append("</script>")
            return

        # keep_if_safe
        threshold = getattr(self.policy, "script_strip_at", Severity.MEDIUM)
        if verdict.severity >= threshold:
            self.stripped_scripts += 1
            self.changed = True
            self._record_verdict("内联脚本", text, verdict, Action.STRIPPED)
            return

        self.kept_scripts += 1
        self._record_verdict("内联脚本", text, verdict, Action.KEPT)
        clean = self._clean_attrs("script", attrs)
        self.out.append(self._tag("script", clean, False))
        self.out.append(text)
        self.out.append("</script>")

    def _record_verdict(self, kind: str, text: str, verdict: JsVerdict, action: Action) -> None:
        # 纯信息级(如仅引用白名单 CDN)不作为告警,避免噪声。
        if verdict.severity <= Severity.INFO:
            return
        rule = "js-" + ("malicious" if verdict.malicious else "suspicious")
        if action in (Action.STRIPPED, Action.REPLACED):
            rule = "js-blocked"
        self._add(rule, verdict.severity, action,
                  f"{kind}: {verdict.summary()}", text[:160])


def sanitize_html(
    html: str,
    policy: Policy,
    analyzer: JsAnalyzer,
    location: str,
    *,
    max_iterations: int = 3,
) -> HtmlResult:
    """净化 HTML 片段,返回安全内容与发现项。"""
    if not html:
        return HtmlResult(html="")

    if len(html) > policy.max_output_chars:
        f = Finding("html-too-large", Severity.HIGH, Action.REPLACED, location,
                    f"HTML 输出超过 {policy.max_output_chars} 字符上限")
        return HtmlResult(html=_esc_text(html[:2000]) + "<!-- output truncated -->",
                          findings=[f], changed=True)

    findings: List[Finding] = []
    seen: set = set()

    def _collect(items: List[Finding]) -> None:
        for f in items:
            key = (f.rule, int(f.severity), f.action, f.location, f.message, f.evidence)
            if key not in seen:
                seen.add(key)
                findings.append(f)

    kept = stripped = 0
    current = html
    changed_any = False
    result: Optional[HtmlResult] = None

    for _ in range(max_iterations):
        rw = _Rewriter(policy, analyzer, location)
        try:
            rw.feed(current)
            rw.close()
            rw.finish_raw()
        except Exception as exc:  # 解析器崩溃 → 安全降级
            f = Finding("html-parse-error", Severity.HIGH, Action.REPLACED, location,
                        f"HTML 解析失败,已替换为纯文本: {type(exc).__name__}")
            return HtmlResult(html=_esc_text(html[:4000]), findings=[f], changed=True)
        # 确保原始文本元素(script/style)在 feed 结束后也被处理
        rw.finish_raw()
        if rw.too_deep:
            f = Finding("html-too-deep", Severity.HIGH, Action.REPLACED, location,
                        "HTML 结构过深,已替换为纯文本")
            return HtmlResult(html=_esc_text(html[:4000]), findings=[f], changed=True)

        new = "".join(rw.out)
        # 每一轮的发现项都要保留:第二轮里原本的恶意脚本已经不存在,
        # 若只取最后一轮会静默丢掉告警。
        _collect(rw.findings)
        kept = max(kept, rw.kept_scripts)
        stripped = max(stripped, rw.stripped_scripts)
        changed_any = changed_any or rw.changed
        result = HtmlResult(new, findings, kept, stripped, changed_any)
        if new == current:
            current = new
            break
        # 若净化会改变输出,再跑一遍;稳定即收敛(mXSS 定点)
        current = new

    # 注入 CSP 由调用方在净化收敛后执行,见 :func:`inject_csp`。
    return result if result else HtmlResult(html=current, findings=findings)


_CSP = (
    "default-src 'none'; "
    "script-src 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com "
    "https://cdnjs.cloudflare.com https://cdn.plot.ly https://d3js.org "
    "https://cdn.bokeh.org https://code.jquery.com; "
    "style-src 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com "
    "https://cdnjs.cloudflare.com https://cdn.plot.ly https://cdn.bokeh.org; "
    "img-src data: blob: https:; font-src data: https:; "
    "connect-src 'none'; frame-src 'none'; object-src 'none'; "
    "base-uri 'none'; form-action 'none'"
)

_CSP_MARK = "Content-Security-Policy"


def _is_own_csp(content: str) -> bool:
    """判断是否为我们注入的 CSP(避免把自产内容当作攻击剥离)。"""
    c = (content or "").strip()
    return c.startswith("default-src 'none'") and "connect-src 'none'" in c


def inject_csp(body: str, csp: str = _CSP) -> str:
    """在片段开头插入 CSP meta(幂等:已存在则替换)。"""
    if not body:
        return body
    existing = re.search(
        r"<meta\b[^>]*http-equiv\s*=\s*[\"']?Content-Security-Policy[\"']?[^>]*>",
        body,
        re.I,
    )
    if existing:
        body = body[: existing.start()] + body[existing.end() :]
    tag = f'<meta http-equiv="Content-Security-Policy" content="{_esc_attr(csp)}">'
    return tag + body


# SVG 中可改变属性/触发动作的元素(防 animate 改写 href 为 javascript:)
SVG_ACTIVE_ELEMENTS = {
    "animate", "set", "animatemotion", "animatetransform", "discard",
    "handler", "listener", "mpath", "cursor",
}


def postcheck_html(body: str, policy: Policy, analyzer: JsAnalyzer) -> bool:
    """净化后置校验:再次净化应当不再改变内容(幂等)。

    返回 True 表示通过。这是对 mXSS / 解析差异的强不变量检查。
    """
    again = sanitize_html(body, policy, analyzer, "<postcheck>", max_iterations=2)
    return again.html == body


def sanitize_static_html(html: str, location: str) -> HtmlResult:
    """仅做静态化:移除所有脚本与嵌入对象,用于 strict 的图表降级。"""
    policy = Policy(name="strict")
    analyzer = JsAnalyzer(policy)
    return sanitize_html(html, policy, analyzer, location)
