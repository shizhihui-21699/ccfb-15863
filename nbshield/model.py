"""结果数据模型:严重级别、处置动作、发现项、报告。"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any, Dict, Iterable, List, Optional


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        return cls[str(name).strip().upper()]


class Action(str, Enum):
    """对某个单元采取的实际处置。"""

    KEPT = "kept"          # 原样保留
    FLAGGED = "flagged"    # 保留但记录(需人工复核)
    REWRITTEN = "rewritten"  # 内容被改写(净化但仍可用)
    STRIPPED = "stripped"  # 移除该活动内容
    REPLACED = "replaced"  # 用安全占位替换
    BLOCKED = "blocked"    # 整个文件被拒绝


_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WS = re.compile(r"\s+")


def _clean_evidence(text: str, limit: int = 240) -> str:
    if not text:
        return ""
    text = _CTRL.sub(" ", text)
    text = _WS.sub(" ", text).strip()
    if len(text) > limit:
        text = text[:limit] + "…"
    return text


@dataclass
class Finding:
    rule: str
    severity: Severity
    action: Action
    location: str
    message: str
    evidence: str = ""

    def __post_init__(self) -> None:
        self.evidence = _clean_evidence(self.evidence)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity.label,
            "action": self.action.value,
            "location": self.location,
            "message": self.message,
            "evidence": self.evidence,
        }

    def line(self) -> str:
        ev = f" | evidence: {self.evidence}" if self.evidence else ""
        return f"[{self.severity.name}] {self.rule} @ {self.location}: {self.message} ({self.action.value}){ev}"


# 平台渲染 HTML 输出时建议设置的 CSP。报告里给出,便于平台侧兜底。
RECOMMENDED_CSP = (
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


@dataclass
class Report:
    policy: str = "balanced"
    source: str = ""
    nbformat: str = ""
    findings: List[Finding] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=dict)
    input_sha256: str = ""
    output_sha256: str = ""
    blocked: bool = False
    block_reason: str = ""
    warnings: List[str] = field(default_factory=list)
    recommended_csp: str = RECOMMENDED_CSP

    # -- 采集 -------------------------------------------------------------
    def add(
        self,
        rule: str,
        severity: Severity,
        action: Action,
        location: str,
        message: str,
        evidence: str = "",
    ) -> Finding:
        f = Finding(rule, severity, action, location, message, evidence)
        self.findings.append(f)
        return f

    def bump(self, key: str, n: int = 1) -> None:
        self.stats[key] = self.stats.get(key, 0) + n

    # -- 汇总 -------------------------------------------------------------
    @property
    def max_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    def counts(self) -> Dict[str, int]:
        out = {s.label: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.label] += 1
        return out

    def by_action(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            out[f.action.value] = out.get(f.action.value, 0) + 1
        return out

    def sorted_findings(self) -> List[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (-int(f.severity), f.location, f.rule),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": "nbshield",
            "policy": self.policy,
            "source": self.source,
            "nbformat": self.nbformat,
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "input_sha256": self.input_sha256,
            "output_sha256": self.output_sha256,
            "max_severity": self.max_severity.label,
            "counts": self.counts(),
            "actions": self.by_action(),
            "stats": dict(sorted(self.stats.items())),
            "warnings": list(self.warnings),
            "recommended_csp": self.recommended_csp,
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }

    def summary(self, max_findings: int = 30) -> str:
        c = self.counts()
        head = (
            f"nbshield: policy={self.policy} max_severity={self.max_severity.label} "
            f"findings={len(self.findings)} "
            f"(critical={c['critical']} high={c['high']} medium={c['medium']} "
            f"low={c['low']} info={c['info']})"
        )
        if self.blocked:
            head += f" BLOCKED: {self.block_reason}"
        lines = [head]
        if self.stats:
            lines.append("stats: " + ", ".join(f"{k}={v}" for k, v in sorted(self.stats.items())))
        shown = self.sorted_findings()[:max_findings]
        for f in shown:
            lines.append("  " + f.line())
        if len(self.findings) > len(shown):
            lines.append(f"  … {len(self.findings) - len(shown)} more findings")
        return "\n".join(lines)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
