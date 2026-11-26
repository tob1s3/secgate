"""Парсеры отчётов сканеров. Формат определяется по содержимому JSON, а не по имени файла."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..models import Finding
from . import bandit, pip_audit, semgrep, trivy

Parser = Callable[[dict[str, Any]], list[Finding]]


class UnknownReportError(ValueError):
    pass


def detect(data: Any) -> tuple[str, Parser]:
    """Узнаёт сканер по характерным полям отчёта."""
    if isinstance(data, dict):
        if "SchemaVersion" in data or "ArtifactName" in data:
            return "trivy", trivy.parse
        if "dependencies" in data and isinstance(data["dependencies"], list):
            return "pip-audit", pip_audit.parse
        results = data.get("results")
        if isinstance(results, list):
            if "generated_at" in data and "metrics" in data:
                return "bandit", bandit.parse
            first = results[0] if results else {}
            if "check_id" in first or ("errors" in data and "paths" in data):
                return "semgrep", semgrep.parse
            if "test_id" in first:
                return "bandit", bandit.parse
    raise UnknownReportError("не удалось определить формат отчёта")


def load_report(path: Path) -> tuple[str, list[Finding]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise UnknownReportError(f"{path}: некорректный JSON ({exc.msg})") from exc
    try:
        name, parser = detect(data)
    except UnknownReportError as exc:
        raise UnknownReportError(f"{path}: {exc}") from None
    return name, parser(data)
