from __future__ import annotations

import json
from datetime import date

import pytest

from secgate.baseline import MAX_DAYS, Baseline, BaselineError
from secgate.models import Finding, Kind, Severity
from secgate.policy import Policy

TODAY = date(2026, 11, 26)


def f(kind=Kind.CODE, sev=Severity.HIGH, rule="R1", path="a.py"):
    return Finding("bandit", kind, rule, sev, "t", path=path)


# --- политика -------------------------------------------------------------------


def test_default_policy_blocks_high():
    assert Policy().violations([f(sev=Severity.HIGH)])
    assert not Policy().violations([f(sev=Severity.MEDIUM), f(sev=Severity.LOW)])


def test_secret_blocks_even_if_low():
    reasons = Policy().violations([f(kind=Kind.SECRET, sev=Severity.LOW)])
    assert reasons == ["найдено секретов в репозитории: 1"]


def test_unknown_as():
    unknown = f(sev=Severity.UNKNOWN)
    assert not Policy().violations([unknown])
    assert Policy(unknown_as=Severity.HIGH).violations([unknown])


def test_policy_from_toml(tmp_path):
    cfg = tmp_path / "secgate.toml"
    cfg.write_text(
        '[policy]\nfail_on = "critical"\nunknown_as = "low"\nblock_secrets = false\n[policy.max_count]\nmedium = 1\n'
    )
    policy = Policy.load(cfg)
    assert policy.fail_on == Severity.CRITICAL
    assert policy.unknown_as == Severity.LOW
    assert not policy.block_secrets
    assert not policy.violations([f(sev=Severity.HIGH), f(sev=Severity.MEDIUM), f(kind=Kind.SECRET)])
    assert policy.violations([f(sev=Severity.MEDIUM), f(sev=Severity.MEDIUM, rule="R2")]) == [
        "находок уровня MEDIUM: 2 (лимит 1)"
    ]


def test_policy_rejects_typo(tmp_path):
    cfg = tmp_path / "secgate.toml"
    cfg.write_text('[policy]\nfail_on = "hihg"\n')
    with pytest.raises(ValueError, match="hihg"):
        Policy.load(cfg)


# --- baseline -------------------------------------------------------------------


def write_baseline(tmp_path, *entries):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"exceptions": list(entries)}))
    return path


def test_baseline_accepts_until_expiry(tmp_path):
    finding = f()
    path = write_baseline(
        tmp_path, {"fingerprint": finding.fingerprint, "reason": "ложное срабатывание", "expires": "2026-12-31"}
    )
    baseline = Baseline.load(path, TODAY)
    new, accepted, expired = baseline.split([finding], TODAY)
    assert (new, accepted, expired) == ([], [finding], [])

    new, accepted, expired = baseline.split([finding], date(2027, 1, 1))
    assert new == [finding] and not accepted
    assert expired[0].reason == "ложное срабатывание"


def test_secret_can_not_be_accepted(tmp_path):
    secret = f(kind=Kind.SECRET)
    path = write_baseline(
        tmp_path, {"fingerprint": secret.fingerprint, "reason": "очень надо", "expires": "2026-12-01"}
    )
    new, accepted, _ = Baseline.load(path, TODAY).split([secret], TODAY)
    assert new == [secret] and not accepted


def test_baseline_matches_any_merged_fingerprint(tmp_path):
    head, other = f(rule="A"), f(rule="B")
    head.merge(other)
    path = write_baseline(tmp_path, {"fingerprint": other.fingerprint, "reason": "r", "expires": "2026-12-01"})
    baseline = Baseline.load(path, TODAY)
    assert baseline.split([head], TODAY)[1] == [head]
    assert baseline.unused([head]) == []


@pytest.mark.parametrize(
    ("entry", "error"),
    [
        ({"fingerprint": "x", "expires": "2026-12-01"}, "reason"),
        ({"fingerprint": "x", "reason": "r"}, "expires"),
        ({"reason": "r", "expires": "2026-12-01"}, "fingerprint"),
        ({"fingerprint": "x", "reason": "r", "expires": "01.12.2026"}, "ГГГГ-ММ-ДД"),
        ({"fingerprint": "x", "reason": "r", "expires": "2030-01-01"}, str(MAX_DAYS)),
    ],
)
def test_baseline_validation(tmp_path, entry, error):
    with pytest.raises(BaselineError, match=error):
        Baseline.load(write_baseline(tmp_path, entry), TODAY)


def test_unused_exceptions(tmp_path):
    path = write_baseline(tmp_path, {"fingerprint": "deadbeef", "reason": "r", "expires": "2026-12-01"})
    baseline = Baseline.load(path, TODAY)
    assert [e.fingerprint for e in baseline.unused([f()])] == ["deadbeef"]
    assert [e.fingerprint for e in baseline.unused([])] == ["deadbeef"]
