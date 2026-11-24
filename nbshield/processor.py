"""笔记本处理器:遍历单元与各类活动面,产出净化后的笔记本与报告。

覆盖:
* 输出:``text/html``、``image/svg+xml``、``application/javascript``、
  ``text/markdown``、``text/latex``、``application/vnd.*``、注释/ANSI、
  ``application/json`` 中的 HTML。
* 元数据:笔记本级、单元级(含 nbconvert / widgets 配置)、输出 metadata。
* 附件:按 MIME 检查同源的 HTML/SVG/JS。
* ipywidgets:``widgets`` 状态(模型 JSON 与模块版本)。
* 结构:magic、代码单元可疑模式(只告警)。

所有改动都记录为 :class:`Finding`,并统计保留/移除的脚本数量,
便于评估"清洗后图表是否仍能显示"。
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from . import patterns
from .htmlsanitizer import inject_csp, postcheck_html, sanitize_html
from .jsanalyze import JsAnalyzer
from .jsonload import NotebookRejected, loads_notebook
from .markdown import sanitize_latex, sanitize_markdown
from .model import Action, Report, Severity, sha256_bytes
from .policy import Policy

# 输出 MIME
MIME_HTML = "text/html"
MIME_SVG = "image/svg+xml"
MIME_JS = "application/javascript"
MIME_MD = "text/markdown"
MIME_LATEX = "text/latex"
MIME_JSON = "application/json"
MIME_PLAIN = "text/plain"
MIME_VND = "application/vnd."
# 这些输出直接包含可执行标记,需处理
HTML_LIKE_MIMES = {MIME_HTML, "text/xhtml", "application/xhtml+xml"}

OUTPUT_CARRIER_MIMES = {
    MIME_HTML, MIME_SVG, MIME_JS, MIME_MD, MIME_LATEX, MIME_JSON,
    "application/xhtml+xml", "text/xhtml", "text/javascript",
    "application/json+widget-state",
}


@dataclass
class ProcessResult:
    notebook: Dict[str, Any]
    report: Report
    text: str = ""


def load_notebook(data: Any, policy: Policy) -> Tuple[Dict[str, Any], List[str]]:
    if isinstance(data, dict):
        # 已解析对象:序列化后走同一条受限解析路径,保证结构/深度/节点数一致。
        try:
            data = json.dumps(data, ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            raise NotebookRejected("unserializable", str(exc)) from exc
    obj, warnings = loads_notebook(
        data,
        max_bytes=policy.max_bytes,
        max_depth=policy.max_depth,
        max_nodes=policy.max_nodes,
    )
    obj = _upgrade_v3(obj, warnings)
    return obj, warnings


# --- v3 -> v4 ------------------------------------------------------------

def _upgrade_v3(nb: Dict[str, Any], warnings: List[str]) -> Dict[str, Any]:
    """把 nbformat 3 的 ``worksheets.cells`` 结构升级到 v4 的 ``cells``。

    只在明显是 v3(有 worksheets 且无 cells)时升级,保留未知字段。
    """
    if "worksheets" not in nb or "cells" in nb:
        return nb
    worksheets = nb.get("worksheets")
    if not isinstance(worksheets, list):
        return nb
    cells: List[Dict[str, Any]] = []
    for ws in worksheets:
        if not isinstance(ws, dict):
            continue
        for c in ws.get("cells") or []:
            if not isinstance(c, dict):
                continue
            cell = dict(c)
            ct = cell.get("cell_type")
            if ct == "code":
                # v3: input, language → v4: source
                if "source" not in cell and "input" in cell:
                    cell["source"] = cell.pop("input")
                cell.setdefault("execution_count", cell.get("prompt_number"))
                cell.setdefault("outputs", [])
                for o in cell.get("outputs") or []:
                    if isinstance(o, dict):
                        if o.get("output_type") == "pyout":
                            o["output_type"] = "execute_result"
                            if "text" in o:
                                o["data"] = {"text/plain": o.pop("text")}
                        elif o.get("output_type") == "stream" and "stream" in o:
                            o["stream"] = {"stdout": "stdout", "stderr": "stderr"}.get(
                                o["stream"], o["stream"]
                            )
                cell.pop("prompt_number", None)
                cell.pop("language", None)
            elif ct == "heading":
                cell["cell_type"] = "markdown"
                level = cell.get("level", 1)
                cell["source"] = "#" * int(level) + " " + str(cell.get("source", ""))
            cell.pop("level", None)
            cells.append(cell)
    out = dict(nb)
    out.pop("worksheets", None)
    out["cells"] = cells
    nbformat = out.get("nbformat", 3)
    out["nbformat"] = 4
    out["nbformat_minor"] = 0
    warnings.append(f"已把 nbformat {nbformat} 升级为 4(v3 结构)")
    return out


# --- 主流程 --------------------------------------------------------------

def process_notebook(
    data: Any,
    policy: Optional[Policy] = None,
    *,
    source: str = "<notebook>",
) -> ProcessResult:
    policy = policy or Policy()
    report = Report(policy=policy.name, source=source)
    if isinstance(data, (bytes, str)):
        report.input_sha256 = sha256_bytes(
            data if isinstance(data, bytes) else data.encode("utf-8", "ignore")
        )

    try:
        nb, warnings = load_notebook(data, policy)
    except NotebookRejected as exc:
        report.blocked = True
        report.block_reason = f"{exc.reason}: {exc.detail}"
        report.add("structure-rejected", Severity.CRITICAL, Action.BLOCKED,
                   "", f"拒绝解析: {exc.reason}", exc.detail)
        return ProcessResult({}, report, "")

    report.warnings.extend(warnings)
    for w in warnings:
        report.add("structure-warning", Severity.MEDIUM, Action.FLAGGED, "",
                   w, "")

    proc = _Processor(policy, report)
    nb = proc.run(nb)

    if policy.verify and not report.blocked:
        _verify(nb, policy, report)

    report.nbformat = f"{nb.get('nbformat', '?')}.{nb.get('nbformat_minor', '?')}"
    if policy.block_on_critical and any(
        f.severity >= Severity.CRITICAL and f.action != Action.FLAGGED
        for f in report.findings
    ):
        # 有确凿恶意内容:默认仍然输出已净化文件,但标记为需拦截
        report.blocked = True
        report.block_reason = "检测到确凿恶意内容(已净化,建议拦截并要求人工复核)"

    text = json.dumps(nb, ensure_ascii=False, indent=1, sort_keys=False) if nb else ""
    report.output_sha256 = sha256_bytes(text.encode("utf-8")) if text else ""
    return ProcessResult(nb, report, text)


# --- 处理器 --------------------------------------------------------------

class _Processor:
    def __init__(self, policy: Policy, report: Report) -> None:
        self.policy = policy
        self.report = report
        self.analyzer = JsAnalyzer(policy, max_chars=policy.max_script_chars)
        self.stats: Dict[str, int] = {}

    def bump(self, k: str, n: int = 1) -> None:
        self.stats[k] = self.stats.get(k, 0) + n

    def add(self, rule: str, sev: Severity, act: Action, loc: str, msg: str, ev: str = "") -> None:
        self.report.add(rule, sev, act, loc, msg, ev)

    # -- 顶层 -------------------------------------------------------------
    def run(self, nb: Dict[str, Any]) -> Dict[str, Any]:
        nb = copy.deepcopy(nb)

        # nbformat 合法性
        fmt = nb.get("nbformat")
        if not isinstance(fmt, int):
            self.add("structure-nbformat", Severity.MEDIUM, Action.FLAGGED, "notebook",
                     "缺少或非法的 nbformat 字段")
        elif fmt < 3:
            self.add("structure-nbformat", Severity.MEDIUM, Action.FLAGGED, "notebook",
                     f"较旧的 nbformat {fmt}")

        cells = nb.get("cells")
        if cells is None:
            cells = []
            nb["cells"] = cells
        if not isinstance(cells, list):
            self.add("structure-cells", Severity.HIGH, Action.REPLACED, "notebook",
                     "cells 不是数组,已替换为空数组")
            nb["cells"] = cells = []

        if len(cells) > self.policy.max_cells:
            self.add("structure-cells", Severity.HIGH, Action.STRIPPED, "notebook",
                     f"单元数 {len(cells)} 超过上限 {self.policy.max_cells},已截断")
            del cells[self.policy.max_cells :]

        self._sanitize_metadata(nb, "notebook.metadata")
        self._sanitize_widget_state(nb)

        for idx, cell in enumerate(cells):
            if isinstance(cell, dict):
                self._process_cell(cell, idx)
            else:
                self.add("structure-cell", Severity.HIGH, Action.REPLACED,
                         f"cells[{idx}]", "单元不是对象,已替换为占位")
                cells[idx] = _placeholder_cell("无效单元")

        self._setup_signature(nb)
        self._fix_ids(nb)
        self.report.stats.update(self.stats)
        return nb

    # -- ipywidgets 状态 ---------------------------------------------------
    def _sanitize_widget_state(self, nb: Dict[str, Any]) -> None:
        """处理 ``metadata.widgets`` 及其 model 状态中的数据与模块版本。

        widgets 状态是 JSON,内嵌的 HTML/JS 字符串同样会被渲染。
        另外校验模块名与版本,防止从任意远程模块加载代码。
        """
        meta = nb.get("metadata")
        if not isinstance(meta, dict):
            return
        widgets = meta.get("widgets")
        if not isinstance(widgets, dict):
            return
        if not self.policy.sanitize_widget_state:
            self.add("widgets-state", Severity.INFO, Action.FLAGGED,
                     "notebook.metadata.widgets",
                     "包含 ipywidgets 状态(策略未处理)")
            return

        # 模块版本:必须是已知前缀,否则降级(防止任意远程模块加载)
        app = widgets.get("application/vnd.jupyter.widget-view+json")
        state = widgets.get("state")
        modules: Dict[str, Any] = {}
        if isinstance(state, dict):
            for model_id, model in state.items():
                if not isinstance(model, dict):
                    continue
                m = model.get("model_module")
                if isinstance(m, str) and m:
                    modules[m] = model.get("model_module_version", "")
                    if not any(m.startswith(p) for p in self.policy.widget_modules):
                        self.add("widget-unknown-module", Severity.HIGH, Action.FLAGGED,
                                 f"notebook.metadata.widgets.state[{model_id}]",
                                 f"未知/可疑的 widget 模块: {m}", m)
                    self.add("widget-module", Severity.INFO, Action.KEPT,
                             f"notebook.metadata.widgets.state[{model_id}]",
                             f"widget 模块 {m}@{model.get('model_module_version', '?')}")
                # 递归清洗 model 内部的所有字符串
                state[model_id] = self._walk_metadata(model, f"widgets.state[{model_id}]", 0)

        if isinstance(state, dict) and state:
            self.add("widgets-state", Severity.LOW, Action.REWRITTEN,
                     "notebook.metadata.widgets",
                     f"已检查 {len(state)} 个 widget 模型状态")
            self.bump("widget_models", len(state))

    # -- 单元 -------------------------------------------------------------
    def _process_cell(self, cell: Dict[str, Any], idx: int) -> None:
        ctype = cell.get("cell_type")
        loc = f"cells[{idx}]"
        if ctype not in ("code", "markdown", "raw"):
            self.add("structure-cell-type", Severity.MEDIUM, Action.FLAGGED, loc,
                     f"未知单元类型 {ctype!r}")

        src = _as_text(cell.get("source"))
        cell["source"] = src

        # 单元元数据(可能是 nbconvert 配置、widgets 视图状态等)
        self._sanitize_metadata(cell, f"{loc}.metadata")

        # 附件:各单元都可能有(markdown 常用)
        self._sanitize_attachments(cell, f"{loc}.attachments")

        if ctype == "markdown":
            if self.policy.markdown_mode != "keep":
                new, fs = sanitize_markdown(src, self.policy, self.analyzer, f"{loc}.source")
                for f in fs:
                    self.report.findings.append(f)
                if new != src:
                    cell["source"] = new
                    self.bump("markdown_sanitized")
                    self.bump("cells_changed")
            self._scan_text_cell(src, loc)
        elif ctype == "raw":
            self._scan_text_cell(src, loc)
        elif ctype == "code":
            self._process_code_cell(cell, src, loc)

    def _scan_text_cell(self, src: str, loc: str) -> None:
        """检测文本单元中的明文/编码活动内容(不改写文本单元源码之外的内容)。"""
        for tok in patterns.scan_text_for_active(src):
            self.add("text-active-marker", Severity.MEDIUM, Action.FLAGGED, loc,
                     f"文本含活动内容特征 {tok!r}", src[:160])
            break
        blobs = patterns.find_encoded_blobs(src, limit=200_000, max_hits=4)
        for b in blobs:
            self.add("obfuscated-payload", Severity.HIGH, Action.FLAGGED, loc,
                     f"文本中发现 {b.kind} 编码块,解码后为 {b.looks_like}", b.decoded_preview)

    # -- 代码单元 ---------------------------------------------------------
    def _process_code_cell(self, cell: Dict[str, Any], src: str, loc: str) -> None:
        new_src = self._check_magic(src, loc)
        if new_src != src:
            cell["source"] = new_src
            src = new_src
        self._check_code_patterns(src, loc)

        outputs = cell.get("outputs")
        if outputs is None:
            return
        if not isinstance(outputs, list):
            self.add("structure-outputs", Severity.HIGH, Action.REPLACED, f"{loc}.outputs",
                     "outputs 不是数组,已清空")
            cell["outputs"] = []
            return

        if self.policy.strip_outputs:
            if outputs:
                self.add("policy-strip-outputs", Severity.LOW, Action.STRIPPED,
                         f"{loc}.outputs", "策略要求移除全部输出")
                cell["outputs"] = []
            return

        new_outputs: List[Dict[str, Any]] = []
        for i, out in enumerate(outputs):
            oloc = f"{loc}.outputs[{i}]"
            if not isinstance(out, dict):
                self.add("structure-output", Severity.MEDIUM, Action.STRIPPED, oloc,
                         "输出项不是对象,已丢弃")
                continue
            cleaned = self._process_output(out, oloc)
            if cleaned is not None:
                new_outputs.append(cleaned)
        cell["outputs"] = new_outputs

    def _check_magic(self, src: str, loc: str) -> str:
        m = re.search(r"^\s*%%(javascript|js|html|HTML|SVG|svg|script|latex|markdown)\b", src)
        if not m:
            return src
        magic = m.group(1).lower()
        sev = Severity.HIGH if magic in ("javascript", "js", "html", "svg", "script") else Severity.MEDIUM
        self.add("code-magic", sev, Action.FLAGGED, loc,
                 f"代码单元使用 %{magic} 魔法,运行时会生成活动内容", src[:160])
        if self.policy.neutralize_magics and magic in ("javascript", "js", "html", "svg", "script"):
            # 把魔法行改成普通注释,使该单元不再产出活动内容;其余代码保留以便阅读。
            first, sep, rest = src.partition("\n")
            body = re.sub(r"^\s*%%\S*\s*", "", first).strip()
            neutralized = "# [nbshield] 已中和活动内容魔法(原 %% %s)" % magic
            if body:
                neutralized += ": " + body
            new_src = neutralized + (sep + rest if sep else "")
            self.add("code-magic-neutralized", Severity.MEDIUM, Action.REWRITTEN, loc,
                     f"已把 %{magic} 魔法行改为注释")
            self.bump("magics_neutralized")
            return new_src
        return src

    def _check_code_patterns(self, src: str, loc: str) -> None:
        """检测运行期执行任意 JS 或读取凭证并外传的 Python 模式(只告警)。"""
        # 1) IPython.display.Javascript / HTML 构造活动内容
        if re.search(r"\b(?:Javascript|HTML)\s*\(", src):
            self.add("code-display-javascript", Severity.HIGH, Action.FLAGGED, loc,
                     "代码构造 Javascript/HTML 输出,运行即可执行脚本", src[:160])
        # 2) os.environ / getpass / 配置文件 + 网络
        secret_hit = re.search(
            r"\b(?:os\.environ|getpass\.|os\.getenv|dotenv|\.aws/credentials|"
            r"keyring|psutil\.Process|\.jupyter/)", src)
        net_hit = re.search(
            r"\b(?:requests\.(?:get|post|put)|urllib\.request|http\.client|"
            r"socket\.|httpx\.|aiohttp\.|boto3|paramiko\.Transport|"
            r"subprocess\.(?:run|call|Popen))\b", src)
        if secret_hit and net_hit:
            self.add("code-exfil-suspect", Severity.CRITICAL, Action.FLAGGED, loc,
                     "代码同时读取环境/凭证并访问网络,疑似外传(需人工复核)", src[:200])
        elif secret_hit:
            self.add("code-secret-access", Severity.MEDIUM, Action.FLAGGED, loc,
                     "代码读取环境变量/凭证", src[:160])
        # 3) 动态执行
        if re.search(r"\b(?:exec|eval|compile)\s*\(|__import__\s*\(|pickle\.loads?\s*\(", src):
            self.add("code-dynamic-exec", Severity.HIGH, Action.FLAGGED, loc,
                     "代码包含动态执行/反序列化(exec/eval/pickle)", src[:160])
        # 4) 下载并执行
        if re.search(r"(?:urlopen|requests\.get|wget|curl)", src) and re.search(
            r"(?:exec|eval|os\.system|subprocess|chmod|\.run\()", src
        ):
            self.add("code-download-exec", Severity.CRITICAL, Action.FLAGGED, loc,
                     "代码疑似下载并执行远程内容", src[:200])
        # 5) 明显的混淆/控制字符
        if patterns.has_bidi_controls(src):
            self.add("code-bidi-control", Severity.HIGH, Action.FLAGGED, loc,
                     "代码含双向文本控制字符(RTL 覆盖,可隐藏代码)")
        blobs = patterns.find_encoded_blobs(src, limit=100_000, max_hits=3)
        for b in blobs:
            self.add("code-obfuscated", Severity.HIGH, Action.FLAGGED, loc,
                     f"代码中发现 {b.kind} 编码块,解码后为 {b.looks_like}", b.decoded_preview)

    # -- 输出 -------------------------------------------------------------
    def _process_output(self, out: Dict[str, Any], loc: str) -> Optional[Dict[str, Any]]:
        otype = out.get("output_type")
        self._sanitize_metadata(out, f"{loc}.metadata")

        if otype == "stream":
            return self._process_stream(out, loc)
        if otype in ("display_data", "execute_result", "pyout"):
            return self._process_data_output(out, loc)
        if otype == "error":
            return self._process_error(out, loc)
        # 未知输出类型:保守丢弃奖励,保留数据但检查
        self.add("output-unknown-type", Severity.MEDIUM, Action.FLAGGED, loc,
                 f"未知输出类型 {otype!r}")
        return out

    def _process_stream(self, out: Dict[str, Any], loc: str) -> Dict[str, Any]:
        text = _as_text(out.get("text"))
        if not text:
            out["text"] = text
            return out
        cleaned, removed = patterns.strip_dangerous_ansi(text)
        if removed:
            self.add("terminal-escape", Severity.HIGH, Action.REWRITTEN, loc,
                     f"移除 {removed} 个危险终端转义序列(OSC/光标控制)")
            self.bump("ansi_sequences_removed", removed)
        # 检测 \r 覆盖隐藏文本(常见于进度条伪造,也可能藏恶意提示)
        if "\r" in cleaned:
            self.bump("stream_carriage_returns")
        out["text"] = cleaned
        return out

    def _process_error(self, out: Dict[str, Any], loc: str) -> Dict[str, Any]:
        if "traceback" in out:
            tb = _as_text(out.get("traceback"))
            cleaned, removed = patterns.strip_dangerous_ansi(tb)
            if removed:
                self.add("terminal-escape", Severity.HIGH, Action.REWRITTEN, loc,
                         f"移除 {removed} 个危险终端转义序列")
            out["traceback"] = cleaned
        out["evalue"] = patterns.strip_control_chars(_as_text(out.get("evalue")))
        out["ename"] = patterns.strip_control_chars(_as_text(out.get("ename")))
        return out

    def _process_data_output(self, out: Dict[str, Any], loc: str) -> Optional[Dict[str, Any]]:
        data = out.get("data")
        if not isinstance(data, dict):
            if data is None:
                return out
            self.add("output-data", Severity.MEDIUM, Action.REPLACED, f"{loc}.data",
                     "data 不是对象,已替换为空对象")
            out["data"] = {}
            return out

        blocked_any = False
        new_data: Dict[str, Any] = {}
        for mime, value in data.items():
            dloc = f"{loc}.data[{mime}]"
            res = self._process_mime(mime, value, dloc)
            if res is _DROP:
                blocked_any = True
                continue
            new_data[mime] = res

        if not new_data and blocked_any:
            # 所有捆绑表示都被移除
            self.add("output-all-blocked", Severity.HIGH, Action.REPLACED, loc,
                     "该输出的全部表示均被移除")
            return _placeholder_output("该输出包含不安全内容,已移除")
        out["data"] = new_data
        # nbformat 4.5 的 ephemeral/metadata 无需特殊处理
        return out

    def _process_mime(self, mime: str, value: Any, loc: str) -> Any:
        ml = (mime or "").lower().strip()

        if ml in HTML_LIKE_MIMES:
            return self._process_html_mime(mime, value, loc, is_svg=False)
        if ml == MIME_SVG:
            return self._process_html_mime(mime, value, loc, is_svg=True)
        if ml == MIME_JS or ml in ("text/javascript", "application/x-javascript"):
            return self._process_js_mime(mime, value, loc)
        if ml == MIME_MD:
            return self._process_md_mime(mime, value, loc)
        if ml == MIME_LATEX:
            text = _as_text(value)
            new, fs = sanitize_latex(text, self.policy, loc)
            for f in fs:
                self.report.findings.append(f)
            if new != text:
                self.bump("latex_sanitized")
            return new
        if ml == MIME_JSON or ml.endswith("+json"):
            return self._process_json_mime(mime, value, loc)
        if ml.startswith("image/") and ml not in (MIME_SVG,):
            # 位图直接保留(浏览器不解码为可执行内容)
            return value
        # 其它(纯文本、PDF 等)原样保留
        return value

    def _process_html_mime(self, mime: str, value: Any, loc: str, *, is_svg: bool) -> Any:
        text = _as_text(value)
        if not text:
            return text
        result = sanitize_html(text, self.policy, self.analyzer, loc)
        for f in result.findings:
            self.report.findings.append(f)
        self.bump("scripts_kept", result.kept_scripts)
        self.bump("scripts_stripped", result.stripped_scripts)
        if result.changed:
            self.bump("html_rewritten")
        body = result.html
        # 后置幂等校验:防 mXSS
        if self.policy.verify and not postcheck_html(body, self.policy, self.analyzer):
            self.add("html-mxss-unstable", Severity.HIGH, Action.REPLACED, loc,
                     "净化结果不稳定(疑似 mXSS),已降级为纯文本")
            body = patterns.strip_control_chars(_strip_tags(body))
            self.bump("html_downgraded")
        if self.policy.inject_csp and not is_svg:
            body = inject_csp(body)
        # 仅当去除 CSP 注入后的实际内容变化才计为改写
        if result.changed:
            self.bump("html_outputs_changed")
        return body

    def _process_js_mime(self, mime: str, value: Any, loc: str) -> Any:
        text = _as_text(value)
        verdict = self.analyzer.analyze(text)
        if self.policy.script_mode == "strip" or self.policy.keep_only_static:
            self.add("js-output-stripped", Severity.LOW, Action.STRIPPED, loc,
                     "策略要求移除 application/javascript 输出")
            return _DROP
        threshold = self.policy.script_strip_at
        if verdict.severity >= threshold:
            self.add("js-output-blocked", verdict.severity, Action.STRIPPED, loc,
                     f"移除 application/javascript 输出: {verdict.summary()}", text[:160])
            self.bump("scripts_stripped")
            return _DROP
        self.bump("scripts_kept")
        return text

    def _process_md_mime(self, mime: str, value: Any, loc: str) -> Any:
        text = _as_text(value)
        new, fs = sanitize_markdown(text, self.policy, self.analyzer, loc)
        for f in fs:
            self.report.findings.append(f)
        if new != text:
            self.bump("markdown_sanitized")
        return new

    def _process_json_mime(self, mime: str, value: Any, loc: str) -> Any:
        """JSON 输出中若嵌入 HTML 字符串,同样处理(如 plotly 的 widget 状态)。"""
        def walk(v: Any, path: str, depth: int) -> Any:
            if depth > 32:
                return v
            if isinstance(v, str):
                if patterns.is_probably_html(v) and any(
                    t in v.lower() for t in ("<script", "<iframe", "onerror=", "javascript:")
                ):
                    r = sanitize_html(v, self.policy, self.analyzer, path)
                    for f in r.findings:
                        self.report.findings.append(f)
                    return r.html
                if patterns.JS_SCHEME_RE.search(v) or patterns.DATA_HTML_RE.search(v):
                    self.add("json-active-url", Severity.HIGH, Action.REWRITTEN, path,
                             "JSON 值含活动协议 URL", v[:120])
                    return "about:blank"
                return v
            if isinstance(v, dict):
                return {k: walk(x, f"{path}.{k}", depth + 1) for k, x in v.items()}
            if isinstance(v, list):
                return [walk(x, f"{path}[{i}]", depth + 1) for i, x in enumerate(v)]
            return v

        return walk(value, loc, 0)

    # -- 元数据 -----------------------------------------------------------
    def _sanitize_metadata(self, holder: Dict[str, Any], loc: str) -> None:
        meta = holder.get("metadata")
        if meta is None:
            return
        if not isinstance(meta, dict):
            self.add("metadata-invalid", Severity.MEDIUM, Action.REPLACED, loc,
                     "metadata 不是对象,已替换")
            holder["metadata"] = {}
            return
        holder["metadata"] = self._walk_metadata(meta, loc, 0)

    def _walk_metadata(self, node: Any, loc: str, depth: int) -> Any:
        if depth > 24:
            self.add("metadata-too-deep", Severity.HIGH, Action.STRIPPED, loc,
                     "metadata 嵌套过深,已截断")
            return {}
        if isinstance(node, dict):
            out: Dict[str, Any] = {}
            for k, v in node.items():
                kloc = f"{loc}.{k}"
                out[k] = self._walk_metadata(v, kloc, depth + 1)
            return out
        if isinstance(node, list):
            return [self._walk_metadata(v, f"{loc}[{i}]", depth + 1) for i, v in enumerate(node)]
        if isinstance(node, str):
            return self._sanitize_metadata_string(node, loc)
        return node

    def _sanitize_metadata_string(self, s: str, loc: str) -> str:
        if not s:
            return s
        # 1) 活动协议
        if patterns.JS_SCHEME_RE.search(s.strip()) or patterns.DATA_HTML_RE.search(s.strip()):
            self.add("metadata-active-url", Severity.HIGH, Action.REWRITTEN, loc,
                     "元数据含活动协议 URL", s[:120])
            return "about:blank"
        # 2) HTML 片段(如 HTML 单元格格式化器、自定义 CSS/JS)
        if patterns.is_probably_html(s):
            r = sanitize_html(s, self.policy, self.analyzer, loc)
            for f in r.findings:
                self.report.findings.append(f)
            self.bump("metadata_html_sanitized")
            return r.html
        # 3) 编码块
        for b in patterns.find_encoded_blobs(s, limit=100_000, max_hits=2):
            if b.looks_like in ("js", "html"):
                self.add("metadata-obfuscated", Severity.HIGH, Action.FLAGGED, loc,
                         f"元数据含 {b.kind} 编码块,解码后为 {b.looks_like}",
                         b.decoded_preview)
        # 4) 控制字符
        if patterns.has_bidi_controls(s):
            self.add("metadata-bidi", Severity.HIGH, Action.REWRITTEN, loc,
                     "元数据含双向文本控制字符,已移除")
            s = "".join(ch for ch in s if ch not in patterns.BIDI_CONTROLS)
        return s

    # -- 附件 -------------------------------------------------------------
    def _sanitize_attachments(self, cell: Dict[str, Any], loc: str) -> None:
        atts = cell.get("attachments")
        if atts is None:
            return
        if not isinstance(atts, dict):
            self.add("attachment-invalid", Severity.MEDIUM, Action.STRIPPED, loc,
                     "attachments 不是对象,已移除")
            cell.pop("attachments", None)
            return
        if self.policy.drop_attachments:
            self.add("attachment-dropped", Severity.LOW, Action.STRIPPED, loc,
                     "策略要求移除全部附件")
            cell.pop("attachments", None)
            return
        new_atts: Dict[str, Any] = {}
        for name, bundle in atts.items():
            nloc = f"{loc}[{name}]"
            if not isinstance(bundle, dict):
                self.add("attachment-invalid", Severity.MEDIUM, Action.STRIPPED, nloc,
                         "附件不是 MIME 对象,已丢弃")
                continue
            new_bundle: Dict[str, Any] = {}
            for mime, content in bundle.items():
                ml = (mime or "").lower().strip()
                if ml in HTML_LIKE_MIMES or ml == MIME_SVG:
                    text = _as_text(content)
                    if ml == MIME_SVG or patterns.is_probably_html(text):
                        r = sanitize_html(text, self.policy, self.analyzer, nloc)
                        for f in r.findings:
                            self.report.findings.append(f)
                        new_bundle[mime] = r.html
                        self.bump("attachments_sanitized")
                        continue
                if ml in (MIME_JS, "text/javascript"):
                    v = self.analyzer.analyze(_as_text(content))
                    if v.severity >= self.policy.script_strip_at:
                        self.add("attachment-js-blocked", v.severity, Action.STRIPPED,
                                 nloc, f"移除附件中的脚本: {v.summary()}")
                        continue
                new_bundle[mime] = content
            if new_bundle:
                new_atts[name] = new_bundle
            else:
                self.bump("attachments_dropped")
        if new_atts:
            cell["attachments"] = new_atts
        else:
            cell.pop("attachments", None)

    # -- 结构收尾 ---------------------------------------------------------
    def _setup_signature(self, nb: Dict[str, Any]) -> None:
        meta = nb.get("metadata")
        if not isinstance(meta, dict):
            return
        if "signature" not in meta:
            return
        if self.policy.strip_notebook_signature:
            self.add("notebook-signature", Severity.INFO, Action.STRIPPED, "notebook.metadata",
                     "移除笔记本签名(导入后签名已失效且可被伪造)")
            meta.pop("signature", None)
        else:
            self.add("notebook-signature", Severity.LOW, Action.FLAGGED, "notebook.metadata",
                     "笔记本携带签名,导入前请用可信密钥验证")

    def _fix_ids(self, nb: Dict[str, Any]) -> None:
        if not self.policy.fix_ids:
            return
        cells = nb.get("cells") or []
        seen: Dict[str, int] = {}
        for i, cell in enumerate(cells):
            if not isinstance(cell, dict):
                continue
            cid = cell.get("id")
            if cid is None:
                continue
            if not isinstance(cid, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", cid):
                newid = _make_id(i, cell)
                self.add("cell-id-invalid", Severity.LOW, Action.REWRITTEN,
                         f"cells[{i}].id", "非法单元 id,已替换", str(cid)[:40])
                cell["id"] = newid
                seen[newid] = seen.get(newid, 0) + 1
            elif cid in seen:
                newid = _make_id(i, cell)
                self.add("cell-id-duplicate", Severity.LOW, Action.REWRITTEN,
                         f"cells[{i}].id", "重复单元 id,已替换", cid)
                cell["id"] = newid
                seen[newid] = 1
            else:
                seen[cid] = 1


# --- 后置校验 ------------------------------------------------------------

_ACTIVE_RESIDUE = (
    "<script", "javascript:", "vbscript:", "onerror=", "onload=", "<iframe",
    "<object", "<embed", "data:text/html",
)


def _verify(nb: Dict[str, Any], policy: Policy, report: Report) -> None:
    """对已净化的笔记本做独立复查,捕获漏网的活动内容。"""
    for i, cell in enumerate(nb.get("cells") or []):
        if not isinstance(cell, dict):
            continue
        for j, out in enumerate(cell.get("outputs") or []):
            if not isinstance(out, dict):
                continue
            data = out.get("data") or {}
            if not isinstance(data, dict):
                continue
            for mime, value in data.items():
                if not isinstance(value, str):
                    continue
                ml = mime.lower()
                if ml in HTML_LIKE_MIMES or ml == MIME_SVG:
                    low = value.lower()
                    # 允许白名单 CSP 与受控脚本,只查明显残留
                    for token in ("javascript:", "vbscript:", "data:text/html"):
                        if token in low:
                            report.add("verify-residue", Severity.CRITICAL, Action.FLAGGED,
                                       f"cells[{i}].outputs[{j}].data[{mime}]",
                                       f"净化后仍残留活动内容 {token!r}")


# --- 辅助 ----------------------------------------------------------------

class _Drop:
    pass


_DROP = _Drop()


def _as_text(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, list):
        return "".join(str(x) for x in v)
    return str(v)


def _placeholder_cell(msg: str) -> Dict[str, Any]:
    return {
        "cell_type": "markdown",
        "metadata": {},
        "source": f"> ⚠️ nbshield: {msg}",
    }


def _placeholder_output(msg: str) -> Dict[str, Any]:
    return {
        "output_type": "display_data",
        "metadata": {},
        "data": {"text/plain": f"[nbshield] {msg}"},
    }


def _make_id(idx: int, cell: Dict[str, Any]) -> str:
    import hashlib
    h = hashlib.sha256(
        (str(idx) + str(cell.get("cell_type")) + _as_text(cell.get("source"))).encode(
            "utf-8", "ignore"
        )
    ).hexdigest()
    return h[:8]


_TAG_RE = re.compile(r"<[^>]*>")


def _strip_tags(s: str) -> str:
    import html as _h
    return _h.unescape(_TAG_RE.sub("", s))
