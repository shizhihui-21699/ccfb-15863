# nbshield

不可信 Jupyter 笔记本的**静态检测与净化**工具。零第三方依赖,从不执行笔记本里的任何代码,也不联网。

针对的真实场景:分析师之间互转、从网上下载的 `.ipynb` 模板里,有人在**输出单元格、元数据、嵌入小部件**里藏脚本,同事一打开就在浏览器里执行,窃取平台登录凭证与数据库连接信息。

```bash
nbshield check    untrusted.ipynb              # 只检测,不写文件
nbshield sanitize untrusted.ipynb -o clean.ipynb
nbshield batch    incoming/ -o clean/ --fail-on high
```

---

## 它解决什么问题

笔记本的威胁面比“代码单元格”更隐蔽。**打开即执行**的内容包括:

| 活动面 | 典型攻击 |
|---|---|
| `text/html` 输出 | `<script>` 读 `document.cookie`/`localStorage` 后 `fetch` 外传;`<img onerror>`;`<form>` 钓鱼 |
| `image/svg+xml` 输出 | `<script>`、`<animate attributeName="href" values="javascript:...">` |
| `application/javascript` 输出 | 直接执行 |
| 单元格/笔记本元数据 | 自定义格式化器、HTML 注解里的脚本;`javascript:` URL |
| ipywidgets `metadata.widgets` | 模型状态里的 HTML;未知远程模块加载 |
| 附件 `attachments` | 伪装成图片的 `text/html`/SVG |
| Markdown 单元格 | 渲染器允许的内嵌 HTML、`javascript:` 链接 |
| `text/latex` | `\href{javascript:...}`、`\htmlClass` 等 MathJax 宏 |
| 终端输出 / `stderr` | OSC 52 写剪贴板(可被粘贴执行)、标题伪造、光标/覆盖欺骗 |

代码单元格只有在**被运行**时才执行,而任意 Python 无法静态净化。工具对运行期风险(`%%javascript` 魔法、`display(Javascript(...))`、`os.environ`+`requests` 外传、`exec`/`pickle.loads`)只做**告警**,不改写分析逻辑,避免破坏正常分析。

## 为什么不能一刀切

正常笔记本里本来就有大量合法的交互图表——Plotly / Bokeh / Altair / Folium 的 HTML 输出**本来就含 `<script>`**。全部剥离会让图表变成空白。

nbshield 的做法是**分级判定**:对每一段脚本做静态安全分析,只有在没有任何外传 sink、没有凭证访问、没有动态代码、没有明显混淆时才保留。

- `plotly`/`bokeh`/`altair` 的内联绘图脚本 → **保留**
- 读 cookie 并 POST 到攻击者的脚本 → **移除**
- 远程脚本只允许白名单 CDN,且强制 `https`
- matplotlib 的静态 SVG、pandas 的 HTML 表格 / Styler → **完整保留**

默认 `balanced` 策略对 dimostrative 的恶意样本能全部拦下,对良性样本零告警(见 `examples/`)。

## 安装与运行

无第三方依赖,Python ≥ 3.9:

```bash
python3 -m nbshield.cli check examples/demo_malicious.ipynb
# 或 pip install -e . 后直接用 nbshield 命令

python3 -m unittest discover -s tests -v
```

## 策略

| 策略 | 适用 | 行为 |
|---|---|---|
| `strict` | 来源完全不可信 | 移除所有脚本/iframe,只留静态内容;图表退化为静态部分;中和魔法 |
| `balanced`(默认) | 一般导入 | 脚本安全判定后保留;远程脚本白名单;注入 CSP;iframe 强制 sandbox |
| `permissive` | 内部半可信 | 只拦确凿凭证外传/动态执行 |
| `monitor` | 审计存量 | 只报告不改写 |

常用覆盖参数:`--script-strip-at {medium,high,critical}`、`--no-csp`、`--allow-iframes`、`--neutralize-magics`、`--strip-outputs`。

## 报告与退出码

`--format text|json|sarif`。退出码:`0` 未达阈值;`1` 达到 `--fail-on` 阈值或检测到确凿恶意内容(默认阻断);`2` 输入错误。

`scan`/`sanitize` 检测到 CRITICAL 时会标记 `blocked` 并返回 1——文件仍被写出(已净化),便于人工复核;确需放行加 `--accept-risk`。

报告里给出 `recommended_csp`,可交给渲染平台做纵深防御。

## 安全不变量(测试保障)

- **幂等**:净化一次与净化两次结果相同;对已净化文件重复处理不再告警、不破坏图表。
- **后置校验**:HTML 净化后再净化必须不改变内容,否则视为疑似 mXSS 降级为纯文本。
- **发现项累积**:多轮迭代中第一轮识别到的恶意脚本,即使第二轮已不存在,告警也不会丢失(避免“静默清洗”)。
- **结构限制**:文件大小、单元数、嵌套深度、节点数、脚本长度均有上限,防止资源耗尽。

## 已知残余风险(务必读)

1. **代码单元格的运行期行为无法静态净化。** 工具会告警,但不会也**不应**自动改写任意 Python。若平台允许用户运行单元格,必须配合内核侧沙箱与网络出口控制——这是最后一道防线。
2. **`balanced` 保留符合“无凭证外传、无动态代码、无混淆”判定的脚本。** 一个刻意构造的、把外传藏进极复杂间接调用的脚本仍可能漏过静态判定。对最敏感的环境用 `strict`,并始终叠加平台级 CSP 与内核沙箱。
3. **CSS 背景图/追踪像素。** 指向外部主机的 CSS `url(...)` 会被阻断(非白名单)并告警;白名单主机的图片仍可被用作追踪像素。
4. **签名不可信。** 导入文件的签名默认剥离——签名只证明“某人用某密钥签过”,不证明内容安全,且可被伪造诱导信任。
5. **NSA/供应链**:本工具零依赖、无网络,降低自身供应链面;但**判定规则**本身需要随新手法更新,建议纳入持续维护与回归样本库。

## 集成建议

```python
from nbshield import process_notebook, get_policy

result = process_notebook(raw_bytes, get_policy("balanced"))
if result.report.blocked:
    ...  # 拒绝导入 / 转人工
result.text            # 净化后的 .ipynb JSON
result.report.to_dict()  # 结构化发现项
```

平台渲染侧同时应:输出沙箱 iframe、限制 CSP `connect-src`、内核禁网白名单。

## 模块

| 文件 | 职责 |
|---|---|
| `jsonload.py` | 受限 JSON 解析(重复键、NaN、深度、节点数、大小) |
| `jslex.py` | JS 词法、转义解码、常量折叠 |
| `jsanalyze.py` | 脚本静态判定(证据组合而非关键词) |
| `htmlsanitizer.py` | HTML/SVG 重建式净化 + mXSS 定点迭代 + CSP |
| `markdown.py` | Markdown 内嵌 HTML 与 LaTeX 宏 |
| `processor.py` | 笔记本遍历、各活动面分发、widgets、附件 |
| `policy.py` | 策略预设 |
| `cli.py` / `sarif.py` | 命令行与 SARIF 输出 |
