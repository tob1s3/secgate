from __future__ import annotations

import json

import pytest

from secgate.models import Finding, Kind, Severity, normalize_package
from secgate.parsers import UnknownReportError, detect, load_report


@pytest.mark.parametrize(
    ("name", "tool"),
    [("bandit.json", "bandit"), ("pip-audit.json", "pip-audit"), ("semgrep.json", "semgrep"), ("trivy.json", "trivy")],
)
def test_detect_by_content(fixtures, name, tool):
    detected, _ = detect(json.loads((fixtures / name).read_text()))
    assert detected == tool


def test_detect_empty_bandit_and_semgrep():
    assert detect({"results": [{"test_id": "B101"}]})[0] == "bandit"
    assert detect({"results": [], "errors": [], "paths": {}})[0] == "semgrep"


@pytest.mark.parametrize("data", [{}, [], {"results": [{"foo": 1}]}, "text"])
def test_detect_unknown(data):
    with pytest.raises(UnknownReportError):
        detect(data)


def test_load_report_broken_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(UnknownReportError, match="некорректный JSON"):
        load_report(bad)


def test_load_report_unknown_format(tmp_path):
    other = tmp_path / "other.json"
    other.write_text('{"hello": "world"}')
    with pytest.raises(UnknownReportError, match="other.json"):
        load_report(other)


def test_bandit(fixtures):
    _, findings = load_report(fixtures / "bandit.json")
    by_rule = {f.rule_id: f for f in findings}
    shell = by_rule["B602"]
    assert shell.kind == Kind.CODE
    assert shell.severity == Severity.HIGH
    assert shell.path == "app.py"  # "./app.py" нормализован
    assert shell.line == 12
    assert "CWE-78" in shell.aliases


def test_bandit_low_confidence_lowers_severity():
    data = {
        "results": [
            {
                "test_id": "B105",
                "issue_severity": "HIGH",
                "issue_confidence": "LOW",
                "issue_text": "x",
                "filename": "a.py",
                "line_number": 1,
            }
        ]
    }
    (finding,) = detect(data)[1](data)
    assert finding.severity == Severity.MEDIUM


def test_semgrep(fixtures):
    _, findings = load_report(fixtures / "semgrep.json")
    by_rule = {f.rule_id.rsplit(".", 1)[-1]: f for f in findings}
    assert by_rule["subprocess-shell-true"].severity == Severity.HIGH  # ERROR → HIGH
    assert by_rule["pickle-loads"].severity == Severity.MEDIUM  # WARNING → MEDIUM
    assert "CWE-78" in by_rule["subprocess-shell-true"].aliases


def test_pip_audit(fixtures):
    _, findings = load_report(fixtures / "pip-audit.json")
    assert len(findings) == 24
    assert all(f.kind == Kind.DEPENDENCY and f.severity == Severity.UNKNOWN for f in findings)
    redos = next(f for f in findings if f.rule_id == "PYSEC-2021-66")
    assert redos.vuln_id == "CVE-2020-28493"
    assert redos.fixed_version == "2.11.3"
    # Заголовок — первая содержательная строка, без Markdown-заголовков «### Impact».
    assert not any(f.title.startswith("#") for f in findings)


def test_trivy(fixtures):
    _, findings = load_report(fixtures / "trivy.json")
    kinds = {f.kind for f in findings}
    assert kinds == {Kind.DEPENDENCY, Kind.CONFIG, Kind.SECRET}
    configs = [f for f in findings if f.kind == Kind.CONFIG]
    assert {f.rule_id for f in configs} == {"AVD-DS-0002", "AVD-DS-0005", "AVD-DS-0026"}  # PASS пропущен
    assert next(f for f in configs if f.rule_id == "AVD-DS-0005").line == 2
    (secret,) = [f for f in findings if f.kind == Kind.SECRET]
    assert secret.severity == Severity.CRITICAL


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("CRITICAL", Severity.CRITICAL),
        ("error", Severity.HIGH),
        ("Moderate", Severity.MEDIUM),
        ("INFO", Severity.LOW),
        ("", Severity.UNKNOWN),
        (None, Severity.UNKNOWN),
        ("whatever", Severity.UNKNOWN),
    ],
)
def test_severity_parse(raw, expected):
    assert Severity.parse(raw) == expected


def test_normalize_package():
    assert normalize_package("PyYAML") == normalize_package("pyyaml") == "pyyaml"
    assert normalize_package("zope.interface") == normalize_package("Zope_Interface") == "zope-interface"
    assert normalize_package(None) == ""


def test_code_fingerprint_ignores_line():
    a = Finding("bandit", Kind.CODE, "B602", Severity.HIGH, "t", path="app.py", line=12)
    b = Finding("bandit", Kind.CODE, "B602", Severity.HIGH, "t", path="./app.py", line=40)
    assert a.fingerprint == b.fingerprint
