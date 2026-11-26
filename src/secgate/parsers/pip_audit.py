"""Отчёт `pip-audit -f json` (SCA для Python-зависимостей).

pip-audit не сообщает критичность, поэтому находки получают UNKNOWN. Если ту же CVE
нашёл Trivy, при дедупликации возьмётся его оценка.
"""

from __future__ import annotations

from typing import Any

from ..models import Finding, Kind, Severity

TOOL = "pip-audit"


def _title(description: str | None, fallback: str) -> str:
    """Первая содержательная строка описания (часто это Markdown с заголовком «### Impact»)."""
    for line in (description or "").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            return line[:200]
    return fallback


def parse(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for dep in data.get("dependencies") or []:
        for v in dep.get("vulns") or []:
            fixes = v.get("fix_versions") or []
            findings.append(
                Finding(
                    tool=TOOL,
                    kind=Kind.DEPENDENCY,
                    rule_id=v["id"],
                    severity=Severity.UNKNOWN,
                    title=_title(v.get("description"), v["id"]),
                    path="requirements",
                    package=dep.get("name"),
                    version=dep.get("version"),
                    fixed_version=fixes[0] if fixes else None,
                    aliases=set(v.get("aliases") or []),
                )
            )
    return findings
