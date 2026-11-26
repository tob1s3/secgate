"""Отчёт `trivy ... --format json` (SchemaVersion 2): уязвимости, мисконфиги, секреты."""

from __future__ import annotations

from typing import Any

from ..models import Finding, Kind, Severity

TOOL = "trivy"


def parse(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for result in data.get("Results") or []:
        target = result.get("Target", "")

        for v in result.get("Vulnerabilities") or []:
            findings.append(
                Finding(
                    tool=TOOL,
                    kind=Kind.DEPENDENCY,
                    rule_id=v["VulnerabilityID"],
                    severity=Severity.parse(v.get("Severity")),
                    title=v.get("Title") or v["VulnerabilityID"],
                    path=target,
                    package=v.get("PkgName"),
                    version=v.get("InstalledVersion"),
                    fixed_version=v.get("FixedVersion") or None,
                    url=v.get("PrimaryURL"),
                )
            )

        for m in result.get("Misconfigurations") or []:
            if m.get("Status", "FAIL") != "FAIL":
                continue
            cause = m.get("CauseMetadata") or {}
            findings.append(
                Finding(
                    tool=TOOL,
                    kind=Kind.CONFIG,
                    rule_id=m.get("AVDID") or m["ID"],
                    severity=Severity.parse(m.get("Severity")),
                    title=m.get("Title") or m.get("Message") or m["ID"],
                    path=target,
                    line=cause.get("StartLine"),
                    url=m.get("PrimaryURL"),
                )
            )

        for s in result.get("Secrets") or []:
            findings.append(
                Finding(
                    tool=TOOL,
                    kind=Kind.SECRET,
                    rule_id=s["RuleID"],
                    severity=Severity.parse(s.get("Severity")),
                    title=s.get("Title") or s["RuleID"],
                    path=target,
                    line=s.get("StartLine"),
                )
            )
    return findings
