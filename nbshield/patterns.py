"""共享的检测模式:活动内容特征、编码块识别与解码。

这些模式同时用于 HTML、SVG、Markdown、元数据、附件与 JSON 检查,
确保任何承载活动内容的角落都用同一套判定。
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Iterable, List, NamedTuple, Optional, Tuple
from urllib.parse import urlsplit

# --- 活动内容特征 -------------------------------------------------------

SCRIPT_TAG_RE = re.compile(r"<\s*script\b", re.I)
HTML_TAG_RE = re.compile(r"<\s*/?\s*[a-zA-Z][^>]*>")
EVENT_ATTR_RE = re.compile(
    r"""\bon[a-z]{3,}\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)""", re.I
)
CSS_URL_RE = re.compile(r"""url\s*\(\s*(['"]?)(.*?)\1\s*\)""", re.I | re.S)
JS_SCHEME_RE = re.compile(r"^\s*(?:javascript|vbscript|livescript)\s*:", re.I)
DATA_HTML_RE = re.compile(r"^\s*data:\s*(?:text/html|application/xhtml\+xml|text/javascript|application/javascript)", re.I)
ACTIVE_SCHEMES = ("javascript:", "vbscript:", "livescript:", "data:text/html")

# 可用于把文档"变成"活动内容的事物
ACTIVE_TOKENS = (
    "<script",
    "<iframe",
    "<object",
    "<embed",
    "<applet",
    "<base ",
    "javascript:",
    "vbscript:",
    " srcdoc",
    "onerror=",
    "onload=",
    "onclick=",
    "onmouseover=",
    "onfocus=",
    "onbegin=",
)

# 凭证/平台敏感标识(仅在与外传或存储访问同时出现时才高置信)
SECRET_TOKENS = (
    "document.cookie",
    "localStorage",
    "sessionStorage",
    "indexedDB",
    "window.name",
    "navigator.clipboard",
    "credentials.get",
    "/api/kernels",
    "/api/sessions",
    "/api/contents",
    "_xsrf",
    "jupyter_token",
    "jupyter-token",
    "api_key",
    "apikey",
    "access_token",
    "authorization",
    "bearer ",
    "aws_access_key_id",
    "aws_secret_access_key",
    "private_key",
    "ssh-rsa",
    "BEGIN OPENSSH PRIVATE KEY",
)

BIDI_CONTROLS = "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f"

# ANSI: 保留颜色(SGR),删除其它(OSC 可设置剪贴板/标题、CSI 可移动光标)
ANSI_CSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
ANSI_OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?")
ANSI_OTHER_RE = re.compile(r"\x1b[^\[\]]")
_SGR_RE = re.compile(r"^\x1b\[[0-9;]*m$")


def strip_dangerous_ansi(text: str) -> Tuple[str, int]:
    """删除 OSC 及其它非 SGR 转义序列,保留颜色。返回 (新文本, 删除数)。"""
    removed = 0

    def _osc(m: "re.Match[str]") -> str:
        nonlocal removed
        removed += 1
        return ""

    text = ANSI_OSC_RE.sub(_osc, text)
    text = ANSI_OTHER_RE.sub(_osc, text)

    def _csi(m: "re.Match[str]") -> str:
        nonlocal removed
        s = m.group(0)
        if _SGR_RE.match(s):
            return s
        removed += 1
        return ""

    text = ANSI_CSI_RE.sub(_csi, text)
    return text, removed


_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x80-\x9f]")


def strip_control_chars(text: str) -> str:
    return _CTRL_RE.sub("", text)


# --- URL 处理 -----------------------------------------------------------

class UrlInfo(NamedTuple):
    raw: str
    scheme: str
    host: str
    is_relative: bool


def classify_url(url: str) -> UrlInfo:
    u = (url or "").strip()
    if not u:
        return UrlInfo(u, "", "", True)
    # 去掉前导控制字符与空白(浏览器会忽略 \x00-\x20 与 \t\n\r)
    u_clean = re.sub(r"[\x00-\x20]+", "", u)
    if u_clean.startswith("//"):
        u_clean = "https:" + u_clean
    try:
        parts = urlsplit(u_clean)
    except ValueError:
        return UrlInfo(u, "invalid", "", False)
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    relative = not scheme and not u_clean.startswith("//")
    return UrlInfo(u, scheme, host, relative)


def host_allowed(host: str, allowed: Iterable[str]) -> bool:
    host = (host or "").lower().rstrip(".")
    if not host:
        return False
    for a in allowed:
        a = a.lower()
        if host == a or host.endswith("." + a):
            return True
    return False


# --- 编码块检测与解码 ---------------------------------------------------

_B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_B64URL_RE = re.compile(r"[A-Za-z0-9_-]{40,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){24,}")
_PCT_RE = re.compile(r"(?:%[0-9a-fA-F]{2}){16,}")
_ESCAPE_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}){12,}")

_JS_INDICATORS = (
    "function",
    "=>",
    "eval(",
    "fetch(",
    "xmlhttprequest",
    "document.",
    "window.",
    "atob",
    "fromcharcode",
    "onreadystatechange",
    "require(",
    "import(",
)

_HTML_INDICATORS = ("<script", "<html", "<iframe", "<svg", "<img", "<body", "<!doctype")

# 明显不是"编码的代码"的高频合法 Base64 前缀(图片/字体/PDF),跳过以减少误报
_BENIGN_B64_PREFIXES = (
    "iVBORw0KGgo",  # PNG
    "/9j/",         # JPEG
    "R0lGOD",       # GIF
    "UklGR",        # WebP
    "PHN2Zy",       # <svg
    "JVBERi0",      # %PDF
    "AAABAA",       # ICO
    "data:image",
)


class BlobHit(NamedTuple):
    kind: str          # 'base64' | 'hex' | 'percent' | 'escape'
    sample: str
    decoded_preview: str
    looks_like: str    # 'js' | 'html' | 'text' | 'binary'


def _try_b64(s: str) -> Optional[bytes]:
    t = s.replace("-", "+").replace("_", "/")
    t += "=" * (-len(t) % 4)
    try:
        return base64.b64decode(t, validate=False)
    except (binascii.Error, ValueError):
        return None


def decode_escapes(s: str) -> str:
    """解码 \\xNN / \\uNNNN 序列(用于 JS 字符串之外的整体文本)。"""
    def _x(m: "re.Match[str]") -> str:
        return chr(int(m.group(1), 16))

    s = re.sub(r"\\x([0-9a-fA-F]{2})", _x, s)
    s = re.sub(r"\\u\{([0-9a-fA-F]{1,6})\}", lambda m: _safe_chr(int(m.group(1), 16)), s)
    s = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: _safe_chr(int(m.group(1), 16)), s)
    return s


def _safe_chr(n: int) -> str:
    try:
        return chr(n)
    except (ValueError, OverflowError):
        return ""


def _looks_like(decoded: str) -> str:
    low = decoded.lower()
    printable = sum(1 for ch in decoded[:512] if ch.isprintable() or ch in "\n\r\t")
    if printable < 0.85 * max(1, min(len(decoded), 512)):
        return "binary"
    if any(t in low for t in _HTML_INDICATORS):
        return "html"
    if sum(1 for t in _JS_INDICATORS if t in low) >= 2:
        return "js"
    return "text"


def find_encoded_blobs(
    text: str, *, limit: int = 200_000, max_hits: int = 32
) -> List[BlobHit]:
    """在任意文本中寻找可解码的编码块。

    只报告能在有界范围内解码、且看起来像代码/HTML 的块,避免对
    正常 Base64 图片与随机 ID 产生大量噪声。
    """
    hits: List[BlobHit] = []
    if not text:
        return hits
    sample_text = text[:limit]

    seen = 0
    for m in _B64_RE.finditer(sample_text):
        blk = m.group(0)
        if blk.startswith(_BENIGN_B64_PREFIXES):
            continue
        if seen >= max_hits:
            break
        seen += 1
        raw = _try_b64(blk)
        if not raw:
            continue
        try:
            dec = raw.decode("utf-8")
        except UnicodeDecodeError:
            kind = _looks_like_bytes(raw)
            if kind in ("js", "html"):
                hits.append(
                    BlobHit("base64", _clip(blk), _clip(raw.decode("latin-1")), kind)
                )
            continue
        kind = _looks_like(dec)
        if kind in ("js", "html"):
            hits.append(BlobHit("base64", _clip(blk), _clip(dec), kind))

    for m in _HEX_RE.finditer(sample_text):
        blk = m.group(0)
        try:
            raw = bytes.fromhex(blk)
        except ValueError:
            continue
        try:
            dec = raw.decode("utf-8")
        except UnicodeDecodeError:
            dec = raw.decode("latin-1")
        kind = _looks_like(dec)
        if kind in ("js", "html"):
            hits.append(BlobHit("hex", _clip(blk), _clip(dec), kind))

    for m in _PCT_RE.finditer(sample_text):
        blk = m.group(0)
        try:
            dec = bytes.fromhex(blk.replace("%", "")).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        kind = _looks_like(dec)
        if kind in ("js", "html"):
            hits.append(BlobHit("percent", _clip(blk), _clip(dec), kind))

    for m in _ESCAPE_RE.finditer(sample_text):
        blk = m.group(0)
        dec = decode_escapes(blk)
        kind = _looks_like(dec)
        if kind in ("js", "html"):
            hits.append(BlobHit("escape", _clip(blk), _clip(dec), kind))

    return hits


def _looks_like_bytes(raw: bytes) -> str:
    try:
        return _looks_like(raw.decode("utf-8"))
    except UnicodeDecodeError:
        return "binary"


def _clip(s: str, n: int = 120) -> str:
    s = re.sub(r"\s+", " ", s).strip()
    return s[:n] + ("…" if len(s) > n else "")


def scan_text_for_active(text: str) -> List[str]:
    """返回命中的活动内容特征(用于元数据/附件/JSON 的粗略筛查)。"""
    if not text:
        return []
    low = text.lower()
    return [t for t in ACTIVE_TOKENS if t in low]


def is_probably_html(value: str) -> bool:
    if not isinstance(value, str) or "<" not in value:
        return False
    return bool(HTML_TAG_RE.search(value)) or SCRIPT_TAG_RE.search(value) is not None


def has_bidi_controls(text: str) -> bool:
    return any(ch in BIDI_CONTROLS for ch in text)
