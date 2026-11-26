from __future__ import annotations

from pathlib import Path

import pytest

from secgate.dedup import deduplicate
from secgate.models import Finding
from secgate.parsers import load_report

FIXTURES = Path(__file__).parent / "fixtures"
REPORTS = ["bandit.json", "pip-audit.json", "semgrep.json", "trivy.json"]


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def report_paths() -> list[Path]:
    return [FIXTURES / name for name in REPORTS]


@pytest.fixture
def all_findings(report_paths: list[Path]) -> list[Finding]:
    raw: list[Finding] = []
    for path in report_paths:
        raw.extend(load_report(path)[1])
    return deduplicate(raw)
