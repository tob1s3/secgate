"""Короткая сводка в Markdown — для GITHUB_STEP_SUMMARY или комментария к PR."""

from __future__ import annotations

from collections import Counter

from ..baseline import Exception_
from ..models import Finding, Severity

_ICON = {
    Severity.CRITICAL: "🟥",
    Severity.HIGH: "🟧",
    Severity.MEDIUM: "🟨",
    Severity.LOW: "🟦",
    Severity.UNKNOWN: "⬜",
}


def _md(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def build(
    new: list[Finding],
    accepted: list[Finding],
    expired: list[Exception_],
    violations: list[str],
    limit: int = 30,
) -> str:
    lines = ["## secgate: результат проверки безопасности", ""]
    lines.append("❌ **Сборка заблокирована**" if violations else "✅ **Блокирующих находок нет**")
    for v in violations:
        lines.append(f"- {v}")
    lines.append("")

    counts = Counter(f.severity for f in new)
    summary = " · ".join(f"{_ICON[s]} {s.name}: {counts[s]}" for s in sorted(Severity, reverse=True))
    lines += [f"Новых находок: **{len(new)}** ({summary}); принято в baseline: {len(accepted)}", ""]

    if new:
        lines += ["| | Тип | Где | Что | Исправление | Источник |", "|---|---|---|---|---|---|"]
        for f in new[:limit]:
            if f.package:
                where = f"{f.package} {f.version}"
            elif f.line:
                where = f"{f.path}:{f.line}"
            else:
                where = f.path
            fix = f.fixed_version or "—"
            lines.append(
                f"| {_ICON[f.severity]} | {f.kind} | `{_md(where)}` | {_md(f.vuln_id)}: {_md(f.title[:90])} "
                f"| {_md(fix)} | {', '.join(sorted(f.sources))} |"
            )
        if len(new) > limit:
            lines.append(f"\n…и ещё {len(new) - limit}. Полный список — в SARIF-отчёте.")
        lines.append("")

    if expired:
        lines.append("### Истёк срок исключений")
        for e in expired:
            lines.append(f"- `{e.fingerprint}` (до {e.expires}, {e.owner or 'владелец не указан'}): {e.reason}")
    return "\n".join(lines) + "\n"
