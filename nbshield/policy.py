"""策略:决定哪些活动内容保留、改写或移除。

三条预设:

* ``strict``   —— 最大化安全:HTML 输出只保留静态内容,移除所有脚本/iframe,
                  代码单元里的 ``%%javascript`` 魔法被中和。图表会退化为静态部分。
* ``balanced`` —— 默认。脚本经静态安全判定后保留(plotly/bokeh/altair 能正常工作),
                  远程脚本只允许白名单 CDN,HTML 输出注入 CSP,iframe 强制 sandbox。
* ``permissive`` —— 只移除确凿的恶意内容,保留更多动态能力(仍有白名单与判定)。
* ``monitor``  —— 只检测不改写,用于先摸清存量的合法用法。
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Dict, FrozenSet, Tuple

from .model import Severity

# 允许从中加载脚本的 CDN(必须 https)。与 CSP 建议保持一致。
DEFAULT_SCRIPT_HOSTS: FrozenSet[str] = frozenset(
    {
        "cdn.jsdelivr.net",
        "unpkg.com",
        "cdnjs.cloudflare.com",
        "cdn.plot.ly",
        "d3js.org",
        "cdn.bokeh.org",
        "code.jquery.com",
        "cdn.skypack.dev",
        "esm.sh",
    }
)

# 允许脚本/图片从中取数据的主机(地图瓦片、topojson 等)。
DEFAULT_DATA_HOSTS: FrozenSet[str] = frozenset(
    {
        "cdn.plot.ly",
        "cdn.jsdelivr.net",
        "unpkg.com",
        "cdnjs.cloudflare.com",
        "d3js.org",
        "cdn.bokeh.org",
        "basemaps.cartocdn.com",
        "a.basemaps.cartocdn.com",
        "b.basemaps.cartocdn.com",
        "c.basemaps.cartocdn.com",
        "d.basemaps.cartocdn.com",
        "tile.openstreetmap.org",
        "a.tile.openstreetmap.org",
        "b.tile.openstreetmap.org",
        "c.tile.openstreetmap.org",
        "server.arcgisonline.com",
        "raw.githubusercontent.com",
        "cdn.rawgit.com",
        "vega.github.io",
        "cdn.vega.github.io",
    }
)

# 允许加载的 ipywidgets 模块前缀(其余模块会被降级,防止远程模块加载)。
DEFAULT_WIDGET_MODULES: Tuple[str, ...] = (
    "@jupyter-widgets/base",
    "@jupyter-widgets/controls",
    "@jupyter-widgets/output",
    "@jupyter-widgets/html-manager",
    "@ipywidgets/",
    "jupyter-matplotlib",
    "jupyter-scatter",
    "ipyaggrid",
    "bqplot",
    "ipyleaflet",
    "ipydatawidgets",
)


@dataclass(frozen=True)
class Policy:
    name: str = "balanced"

    # --- 脚本 ---
    script_mode: str = "keep_if_safe"  # keep_if_safe | strip | keep_all
    # keep_if_safe 下,判定达到该级别即移除脚本。
    # balanced: MEDIUM(允许纯绘图脚本,拒绝任何可疑网络/暗写)
    # permissive: CRITICAL(仅移除确凿的凭证外传/动态执行)
    script_strip_at: Severity = Severity.MEDIUM
    allow_remote_scripts: bool = True
    script_hosts: FrozenSet[str] = DEFAULT_SCRIPT_HOSTS
    data_hosts: FrozenSet[str] = DEFAULT_DATA_HOSTS

    # --- HTML ---
    allow_iframes: bool = True
    iframe_sandbox: str = "allow-scripts"
    inject_csp: bool = True
    allow_inline_events: bool = False
    strip_comments: bool = True
    sanitize_css: bool = True

    # --- 其它活动面 ---
    latex_mode: str = "sanitize"     # sanitize | strip | keep
    markdown_mode: str = "sanitize"  # sanitize | keep
    drop_attachments: bool = False
    neutralize_magics: bool = False
    strip_outputs: bool = False
    keep_only_static: bool = False

    # --- 结构/资源限制 ---
    max_bytes: int = 32 * 1024 * 1024
    max_cells: int = 5000
    max_depth: int = 200
    max_nodes: int = 4_000_000
    max_output_chars: int = 8 * 1024 * 1024
    max_script_chars: int = 4 * 1024 * 1024
    max_deobf_bytes: int = 4 * 1024 * 1024

    # --- widgets ---
    widget_modules: Tuple[str, ...] = DEFAULT_WIDGET_MODULES
    sanitize_widget_state: bool = True

    # --- 收尾 ---
    block_on_critical: bool = True
    strip_notebook_signature: bool = True
    fix_ids: bool = True
    verify: bool = True

    def replace(self, **kw) -> "Policy":
        return replace(self, **kw)


def _strict() -> Policy:
    return Policy(
        name="strict",
        script_mode="strip",
        allow_remote_scripts=False,
        allow_iframes=False,
        inject_csp=True,
        latex_mode="strip",
        neutralize_magics=True,
        drop_attachments=False,
        keep_only_static=True,
    )


def _balanced() -> Policy:
    return Policy(name="balanced")


def _permissive() -> Policy:
    return Policy(
        name="permissive",
        script_strip_at=Severity.CRITICAL,
        allow_iframes=True,
        iframe_sandbox="allow-scripts allow-forms",
        inject_csp=False,
        latex_mode="sanitize",
        block_on_critical=True,
    )


def _monitor() -> Policy:
    # 只报告不改写:用于审计存量。
    return Policy(
        name="monitor",
        script_mode="keep_all",
        allow_iframes=True,
        iframe_sandbox="",
        inject_csp=False,
        latex_mode="keep",
        markdown_mode="keep",
        neutralize_magics=False,
        sanitize_widget_state=False,
        strip_notebook_signature=False,
        block_on_critical=False,
        verify=False,
    )


PRESETS: Dict[str, Policy] = {
    "strict": _strict(),
    "balanced": _balanced(),
    "permissive": _permissive(),
    "monitor": _monitor(),
}


def get_policy(name: str = "balanced") -> Policy:
    key = (name or "balanced").strip().lower()
    if key not in PRESETS:
        raise ValueError(
            f"unknown policy {name!r}; choose from: {', '.join(sorted(PRESETS))}"
        )
    return PRESETS[key]
