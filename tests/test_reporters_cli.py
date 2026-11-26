from __future__ import annotations

import json
from datetime import date

import jsonschema
import pytest

from secgate.baseline import Exception_
from secgate.cli import EXIT_BLOCKED, EXIT_ERROR, EXIT_OK, main
from secgate.models import Finding, Kind, Severity
from secgate.reporters import markdown, prometheus, sarif

# --- SARIF ----------------------------------------------------------------------


def test_sarif_is_valid_against_official_schema(fixtures, all_findings):
    schema = json.loads((fixtures / "sarif-schema-2.1.0.json").read_text())
    doc = sarif.build(all_findings)
    jsonschema.validate(doc, schema)
    run = doc["runs"][0]
    assert len(run["results"]) == len(all_findings)
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {r["ruleId"] for r in run["results"]} <= rule_ids
    assert all("secgate/v1" in r["partialFingerprints"] for r in run["results"])


def test_sarif_dependency_message():
    fixed = Finding("trivy", Kind.DEPENDENCY, "CVE-1", Severity.HIGH, "t", package="a", version="1", fixed_version="2")
    nofix = Finding("trivy", Kind.DEPENDENCY, "CVE-2", Severity.LOW, "t", package="b", version="1")
    results = sarif.build([fixed, nofix])["runs"][0]["results"]
    assert "обновить до 2" in results[0]["message"]["text"]
    assert "исправления нет" in results[1]["message"]["text"]
    assert results[0]["level"] == "error" and results[1]["level"] == "note"


# --- Markdown -------------------------------------------------------------------


def test_markdown_blocked(all_findings):
    text = markdown.build(all_findings, [], [], ["найдено секретов в репозитории: 1"])
    assert "Сборка заблокирована" in text
    assert "найдено секретов" in text
    assert "`pyyaml 5.3`" in text


def test_markdown_pass_with_expired_and_limit():
    items = [Finding("bandit", Kind.CODE, f"B{i}", Severity.LOW, "a|b", path="x.py", line=i) for i in range(5)]
    exc = Exception_("abc", "временно", date(2026, 1, 1))
    text = markdown.build(items, [], [exc], [], limit=2)
    assert "пройдена" in text.lower() or "✅" in text
    assert "a\\|b" in text  # экранирование вертикальной черты
    assert "abc" in text
    assert "ещё 3" in text


# --- Prometheus -----------------------------------------------------------------


def test_prometheus(all_findings):
    text = prometheus.build('team"a', all_findings, [], blocked=True)
    assert 'project="team\\"a"' in text
    assert 'secgate_gate_blocked{project="team\\"a"} 1' in text
    assert 'secgate_findings{project="team\\"a",severity="critical",kind="secret",status="new"} 1' in text
    fixable = sum(1 for f in all_findings if f.fixed_version)
    assert f'secgate_fixable_findings{{project="team\\"a"}} {fixable}' in text


# --- CLI ------------------------------------------------------------------------


def test_cli_blocks_on_fixtures(report_paths, tmp_path, capsys):
    out_sarif, out_md, out_prom = tmp_path / "r.sarif", tmp_path / "s.md", tmp_path / "m.prom"
    code = main(
        ["check", *map(str, report_paths), "--today", "2026-11-26", "--sarif", str(out_sarif)]
        + ["--markdown", str(out_md), "--metrics", str(out_prom), "--project", "demo"]
    )
    assert code == EXIT_BLOCKED
    assert json.loads(out_sarif.read_text())["version"] == "2.1.0"
    assert "Сборка заблокирована" in out_md.read_text()
    assert 'secgate_gate_blocked{project="demo"} 1' in out_prom.read_text()
    assert "ЗАБЛОКИРОВАНО" in capsys.readouterr().err


def test_cli_passes_with_relaxed_policy_and_baseline(fixtures, tmp_path, capsys):
    # Только код из Bandit: CRITICAL нет, секрета нет → под политикой fail_on=critical гейт проходит.
    policy = tmp_path / "p.toml"
    policy.write_text('[policy]\nfail_on = "critical"\n')
    code = main(["check", str(fixtures / "bandit.json"), "--policy", str(policy), "--today", "2026-11-26"])
    assert code == EXIT_OK
    assert "пройдено" in capsys.readouterr().err


def test_cli_baseline_accepts_finding(fixtures, tmp_path, capsys):
    main(["fingerprints", str(fixtures / "bandit.json")])
    lines = capsys.readouterr().out.splitlines()
    high = [line.split()[0] for line in lines if " HIGH " in line]
    baseline = tmp_path / "b.json"
    baseline.write_text(
        json.dumps({"exceptions": [{"fingerprint": fp, "reason": "пример", "expires": "2026-12-31"} for fp in high]})
    )
    code = main(["check", str(fixtures / "bandit.json"), "--baseline", str(baseline), "--today", "2026-11-26"])
    assert code == EXIT_OK


def test_cli_markdown_goes_to_step_summary(fixtures, tmp_path, monkeypatch):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    main(["check", str(fixtures / "bandit.json"), "--today", "2026-11-26"])
    assert "secgate" in summary.read_text()


def test_cli_prints_summary_without_target(fixtures, monkeypatch, capsys):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    main(["check", str(fixtures / "semgrep.json"), "--today", "2026-11-26"])
    assert "## secgate" in capsys.readouterr().out


@pytest.mark.parametrize("content", ["{broken", '{"hello": 1}'])
def test_cli_error_exit_code(tmp_path, content, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text(content)
    assert main(["check", str(bad)]) == EXIT_ERROR
    assert "ошибка" in capsys.readouterr().err


def test_cli_invalid_baseline(fixtures, tmp_path):
    baseline = tmp_path / "b.json"
    baseline.write_text('{"exceptions": [{"fingerprint": "x"}]}')
    assert main(["check", str(fixtures / "bandit.json"), "--baseline", str(baseline)]) == EXIT_ERROR


def test_cli_reports_unused_exception(fixtures, tmp_path, capsys):
    baseline = tmp_path / "b.json"
    baseline.write_text('{"exceptions": [{"fingerprint": "deadbeef", "reason": "r", "expires": "2026-12-01"}]}')
    main(["check", str(fixtures / "semgrep.json"), "--baseline", str(baseline), "--today", "2026-11-26"])
    assert "deadbeef больше не нужно" in capsys.readouterr().err


def test_module_entrypoint():
    import runpy
    import sys

    sys.argv = ["secgate", "--version"]
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("secgate", run_name="__main__")
    assert exc.value.code == 0
