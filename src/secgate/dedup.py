"""Дедупликация: одна проблема от нескольких сканеров превращается в одну находку.

Два прохода:
1. Точное совпадение отпечатка. Для зависимостей отпечаток не зависит от сканера,
   поэтому CVE, найденная и Trivy, и pip-audit, сливается здесь.
2. Корреляция кода: Bandit и Semgrep по-разному называют правила, но если оба
   указали на одну строку одного файла с одним и тем же CWE — это одна проблема.
"""

from __future__ import annotations

from collections.abc import Iterable

from .models import Finding, Kind


def _by_fingerprint(findings: Iterable[Finding]) -> list[Finding]:
    merged: dict[str, Finding] = {}
    for f in findings:
        if f.fingerprint in merged:
            merged[f.fingerprint].merge(f)
        else:
            merged[f.fingerprint] = f
    return list(merged.values())


def _correlate_code(findings: list[Finding]) -> list[Finding]:
    groups: dict[tuple[str, int, str], list[Finding]] = {}
    rest: list[Finding] = []
    for f in findings:
        if f.kind == Kind.CODE and f.line is not None and f.cwe:
            groups.setdefault((f.path, f.line, f.cwe), []).append(f)
        else:
            rest.append(f)
    for group in groups.values():
        # Представитель выбирается детерминированно, чтобы отпечаток не «прыгал» между запусками.
        group.sort(key=lambda f: (f.tool, f.rule_id))
        head = group[0]
        for other in group[1:]:
            head.merge(other)
        rest.append(head)
    return rest


def deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    result = _correlate_code(_by_fingerprint(findings))
    return sorted(result, key=lambda f: (-f.severity, f.kind, f.path, f.line or 0, f.rule_id))
