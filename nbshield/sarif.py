"""SARIF 2.1.0 输出,便于接入 CI / 代码扫描平台。"""

from __future__ import annotations

from typing import Any, Dict, List

_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def to_sarif(reports: List[Any]) -> Dict[str, Any]:
    results = []
    rules: Dict[str, Dict[str, Any]] = {}
    for rep in reports:
        for f in rep.sorted_findings():
            rule_id = f"nbshield/{f.rule}"
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "name": f.rule,
                    "shortDescription": {"text": f.message},
                    "properties": {"severity": f.severity.label},
                },
            )
            results.append(
                {
                    "ruleId": rule_id,
                    "level": _SARIF_LEVEL.get(f.severity.label, "warning"),
                    "message": {"text": f.message},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": rep.source or "<notebook>"},
                                "region": {"startLine": 1},
                            },
                            "logicalLocations": [{"fullyQualifiedName": f.location}],
                        }
                    ],
                    "properties": {
                        "action": f.action.value,
                        "evidence": f.evidence,
                    },
                }
            )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "nbshield",
                        "informationUri": "https://example.invalid/nbshield",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
