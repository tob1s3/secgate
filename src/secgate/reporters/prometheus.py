"""Метрики в текстовом формате Prometheus (node_exporter textfile collector или Pushgateway).

Позволяют строить в Grafana тренд: сколько уязвимостей открыто в каждом проекте и
сколько из них «висит» в исключениях.
"""

from __future__ import annotations

from collections import Counter

from ..models import Finding, Severity


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def build(project: str, new: list[Finding], accepted: list[Finding], blocked: bool) -> str:
    p = _escape(project)
    out = [
        "# HELP secgate_findings Количество находок по уровню, типу и статусу.",
        "# TYPE secgate_findings gauge",
    ]
    for status, items in (("new", new), ("accepted", accepted)):
        counts = Counter((f.severity, f.kind) for f in items)
        for sev in sorted(Severity, reverse=True):
            for kind in ("dependency", "code", "config", "secret"):
                out.append(
                    f'secgate_findings{{project="{p}",severity="{sev.name.lower()}",'
                    f'kind="{kind}",status="{status}"}} {counts[(sev, kind)]}'
                )
    fixable = sum(1 for f in new if f.fixed_version)
    out += [
        "# HELP secgate_fixable_findings Новые находки в зависимостях, для которых есть исправленная версия.",
        "# TYPE secgate_fixable_findings gauge",
        f'secgate_fixable_findings{{project="{p}"}} {fixable}',
        "# HELP secgate_gate_blocked 1, если гейт заблокировал сборку.",
        "# TYPE secgate_gate_blocked gauge",
        f'secgate_gate_blocked{{project="{p}"}} {int(blocked)}',
    ]
    return "\n".join(out) + "\n"
