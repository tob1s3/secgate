"""Отчёт `semgrep --json` (SAST, много языков)."""

from __future__ import annotations

import re
from typing import Any

from ..models import Finding, Kind, Severity

TOOL = "semgrep"
_CWE_RE = re.compile(r"CWE-\d+")


def parse(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for r in data.get("results") or []:
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        cwes = meta.get("cwe") or []
        if isinstance(cwes, str):
            cwes = [cwes]
        aliases = {m.group(0) for c in cwes if (m := _CWE_RE.search(c))}
        findings.append(
            Finding(
                tool=TOOL,
                kind=Kind.CODE,
                rule_id=r["check_id"],
                severity=Severity.parse(extra.get("severity")),
                title=(extra.get("message") or r["check_id"]).strip(),
                path=r.get("path", ""),
                line=(r.get("start") or {}).get("line"),
                aliases=aliases,
                url=meta.get("source"),
            )
        )
    return findings
