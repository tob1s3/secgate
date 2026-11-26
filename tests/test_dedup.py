from __future__ import annotations

from secgate.dedup import deduplicate
from secgate.models import Finding, Kind, Severity


def dep(tool, pkg, rule, sev=Severity.UNKNOWN, aliases=(), title="t"):
    return Finding(tool, Kind.DEPENDENCY, rule, sev, title, package=pkg, version="5.3", aliases=set(aliases))


def test_same_cve_from_trivy_and_pip_audit_is_one_finding():
    pa = dep("pip-audit", "pyyaml", "PYSEC-2020-96", aliases={"CVE-2020-1747"}, title="long description ...")
    tr = dep("trivy", "PyYAML", "CVE-2020-1747", Severity.CRITICAL, title="PyYAML: RCE")
    (merged,) = deduplicate([pa, tr])
    assert merged.severity == Severity.CRITICAL
    assert merged.sources == {"pip-audit", "trivy"}
    assert merged.title == "PyYAML: RCE"  # заголовок от сканера с оценкой критичности
    assert merged.vuln_id == "CVE-2020-1747"


def test_different_cves_stay_separate():
    a = dep("trivy", "pyyaml", "CVE-2020-1747", Severity.CRITICAL)
    b = dep("trivy", "pyyaml", "CVE-2020-14343", Severity.CRITICAL)
    assert len(deduplicate([a, b])) == 2


def test_fingerprint_is_stable_after_merge():
    pa = dep("pip-audit", "pyyaml", "PYSEC-2020-96", aliases={"CVE-2020-1747"})
    before = pa.fingerprint
    pa.merge(dep("trivy", "pyyaml", "CVE-2020-1747", Severity.HIGH, aliases={"CVE-2000-0001"}))
    # Новый алиас «меньше» исходного CVE, но отпечаток не должен измениться.
    assert pa.fingerprint == before


def test_bandit_and_semgrep_on_same_line_and_cwe_are_correlated():
    b = Finding("bandit", Kind.CODE, "B602", Severity.HIGH, "shell", path="app.py", line=12, aliases={"CWE-78"})
    s = Finding("semgrep", Kind.CODE, "rules.shell", Severity.HIGH, "shell", path="app.py", line=12, aliases={"CWE-78"})
    (merged,) = deduplicate([s, b])
    assert merged.tool == "bandit"  # представитель выбирается детерминированно
    assert merged.sources == {"bandit", "semgrep"}
    assert merged.fingerprints == {b.fingerprint, s.fingerprint}


def test_code_with_different_cwe_is_not_correlated():
    b = Finding("bandit", Kind.CODE, "B506", Severity.MEDIUM, "yaml", path="app.py", line=17, aliases={"CWE-20"})
    s = Finding("semgrep", Kind.CODE, "yaml", Severity.HIGH, "yaml", path="app.py", line=17, aliases={"CWE-502"})
    assert len(deduplicate([b, s])) == 2


def test_fixture_dedup(all_findings):
    # 45 сырых находок → 24 уникальные: дубли pip-audit, пересечение с Trivy и Bandit/Semgrep.
    assert len(all_findings) == 24
    assert all_findings[0].severity == Severity.CRITICAL
    severities = [f.severity for f in all_findings]
    assert severities == sorted(severities, reverse=True)
    both = [f for f in all_findings if f.sources == {"pip-audit", "trivy"}]
    assert len(both) == 7
