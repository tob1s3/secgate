"""Командная строка.

Коды выхода (удобно для CI):
    0 — блокирующих находок нет;
    1 — гейт сработал, сборку нужно остановить;
    2 — ошибка входных данных (битый отчёт, неверный baseline/политика).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date
from pathlib import Path

from . import __version__
from .baseline import Baseline, BaselineError
from .dedup import deduplicate
from .models import Finding
from .parsers import UnknownReportError, load_report
from .policy import Policy
from .reporters import markdown, prometheus, sarif

EXIT_OK, EXIT_BLOCKED, EXIT_ERROR = 0, 1, 2


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secgate", description=__doc__.splitlines()[0])
    p.add_argument("--version", action="version", version=f"secgate {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="проверить отчёты сканеров и вынести вердикт")
    check.add_argument("reports", nargs="+", type=Path, help="JSON-отчёты сканеров")
    check.add_argument("--policy", type=Path, help="TOML с секцией [policy]")
    check.add_argument("--baseline", type=Path, help="JSON со списком принятых рисков")
    check.add_argument("--sarif", type=Path, help="куда записать SARIF")
    check.add_argument("--markdown", type=Path, help="куда записать сводку (по умолчанию — GITHUB_STEP_SUMMARY)")
    check.add_argument("--metrics", type=Path, help="куда записать метрики Prometheus")
    check.add_argument("--project", default=os.environ.get("GITHUB_REPOSITORY", "local"))
    check.add_argument("--today", type=date.fromisoformat, help=argparse.SUPPRESS)

    fp = sub.add_parser("fingerprints", help="показать отпечатки находок (для заполнения baseline)")
    fp.add_argument("reports", nargs="+", type=Path)
    return p


def _collect(paths: list[Path]) -> list[Finding]:
    raw: list[Finding] = []
    for path in paths:
        name, findings = load_report(path)
        print(f"secgate: {path} — {name}, находок: {len(findings)}", file=sys.stderr)
        raw.extend(findings)
    return deduplicate(raw)


def _check(args: argparse.Namespace) -> int:
    today = args.today or date.today()
    findings = _collect(args.reports)
    policy = Policy.load(args.policy) if args.policy else Policy()
    baseline = Baseline.load(args.baseline, today) if args.baseline else Baseline.empty()

    new, accepted, expired = baseline.split(findings, today)
    violations = policy.violations(new)
    blocked = bool(violations)

    for unused in baseline.unused(findings):
        print(f"secgate: исключение {unused.fingerprint} больше не нужно — удалите его из baseline", file=sys.stderr)

    if args.sarif:
        args.sarif.write_text(json.dumps(sarif.build(new), ensure_ascii=False, indent=2), encoding="utf-8")
    summary = markdown.build(new, accepted, expired, violations)
    md_target = args.markdown or (
        Path(os.environ["GITHUB_STEP_SUMMARY"]) if os.environ.get("GITHUB_STEP_SUMMARY") else None
    )
    if md_target:
        with md_target.open("a", encoding="utf-8") as fh:
            fh.write(summary)
    else:
        print(summary)
    if args.metrics:
        args.metrics.write_text(prometheus.build(args.project, new, accepted, blocked), encoding="utf-8")

    verdict = "ЗАБЛОКИРОВАНО: " + "; ".join(violations) if blocked else "пройдено"
    print(f"secgate: {len(findings)} уникальных находок, новых {len(new)} — {verdict}", file=sys.stderr)
    return EXIT_BLOCKED if blocked else EXIT_OK


def _fingerprints(args: argparse.Namespace) -> int:
    for f in _collect(args.reports):
        where = f"{f.package} {f.version}" if f.package else f.path
        print(f"{f.fingerprint}  {f.severity.name:<8} {f.kind:<10} {f.vuln_id}  {where}")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "check":
            return _check(args)
        return _fingerprints(args)
    except (UnknownReportError, BaselineError, ValueError, OSError) as exc:
        print(f"secgate: ошибка: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
