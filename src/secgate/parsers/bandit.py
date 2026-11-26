"""Отчёт `bandit -f json` (SAST для Python)."""

from __future__ import annotations

from typing import Any

from ..models import Finding, Kind, Severity

TOOL = "bandit"

# Находки с низкой уверенностью Bandit часто ложные — понижаем их на ступень.
_CONFIDENCE_PENALTY = {"LOW": 1}


def parse(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for r in data.get("results") or []:
        severity = Severity.parse(r.get("issue_severity"))
        penalty = _CONFIDENCE_PENALTY.get((r.get("issue_confidence") or "").upper(), 0)
        if penalty and severity > Severity.LOW:
            severity = Severity(severity - penalty)
        cwe = (r.get("issue_cwe") or {}).get("id")
        findings.append(
            Finding(
                tool=TOOL,
                kind=Kind.CODE,
                rule_id=r["test_id"],
                severity=severity,
                title=r.get("issue_text") or r.get("test_name") or r["test_id"],
                path=r.get("filename", ""),
                line=r.get("line_number"),
                aliases={f"CWE-{cwe}"} if cwe else set(),
                url=r.get("more_info"),
            )
        )
    return findings
