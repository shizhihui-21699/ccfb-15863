"""nbshield —— 不可信 Jupyter 笔记本的静态检测与净化。

设计边界(很重要):

* 本工具只做**静态分析**,从不执行笔记本里的任何代码,也不联网。
* "打开即执行"的路径是主要防线:输出单元格(text/html、image/svg+xml、
  application/javascript、text/markdown)、单元格/笔记本元数据、
  ipywidgets 状态、附件、Markdown 里的内嵌 HTML。
* 代码单元格只有在被"运行"时才执行,而任意 Python 无法静态净化。
  因此对 ``%%javascript`` / ``display(Javascript(...))`` / 凭证读取 + 外传
  这类可疑模式只做**告警**,不改写源码(除非显式开启 ``--neutralize-magics``),
  以免破坏分析师正常的分析逻辑。
"""

from .model import Finding, Report, Severity, Action
from .policy import Policy, get_policy, PRESETS
from .processor import process_notebook, load_notebook, ProcessResult

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "Finding",
    "Report",
    "Severity",
    "Action",
    "Policy",
    "PRESETS",
    "get_policy",
    "process_notebook",
    "load_notebook",
    "ProcessResult",
]
