"""SARIF 2.1.0 — формат, который понимает GitHub Code Scanning и большинство IDE."""

from __future__ import annotations

from typing import Any

from .. import __version__
from ..models import Finding, Severity

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.UNKNOWN: "warning",
}
# GitHub сортирует находки по security-severity (0–10).
_SCORE = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "2.0",
    Severity.UNKNOWN: "5.0",
}


def build(findings: list[Finding]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for f in findings:
        rule_id = f"{f.kind}/{f.vuln_id}"
        if rule_id not in rules:
            rule: dict[str, Any] = {
                "id": rule_id,
                "shortDescription": {"text": f.title[:200]},
                "properties": {"security-severity": _SCORE[f.severity], "tags": ["security", f.kind]},
            }
            if f.url:
                rule["helpUri"] = f.url
            rules[rule_id] = rule
        location: dict[str, Any] = {"artifactLocation": {"uri": f.path or "."}}
        if f.line:
            location["region"] = {"startLine": f.line}
        message = f.title
        if f.package:
            message += f" ({f.package} {f.version}"
            message += f" → обновить до {f.fixed_version})" if f.fixed_version else ", исправления нет)"
        results.append(
            {
                "ruleId": rule_id,
                "level": _LEVEL[f.severity],
                "message": {"text": message},
                "locations": [{"physicalLocation": location}],
                "partialFingerprints": {"secgate/v1": f.fingerprint},
                "properties": {"sources": sorted(f.sources)},
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secgate",
                        "version": __version__,
                        "informationUri": "https://github.com/tob1s3/secgate",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
