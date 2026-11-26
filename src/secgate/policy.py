"""Политика гейта: при каких находках сборка падает."""

from __future__ import annotations

import tomllib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .models import Finding, Kind, Severity


@dataclass
class Policy:
    # Сборка падает, если есть хотя бы одна новая находка этого уровня или выше.
    fail_on: Severity = Severity.HIGH
    # Дополнительные лимиты по количеству, например {"MEDIUM": 10}.
    max_count: dict[Severity, int] = field(default_factory=dict)
    # Секреты блокируют всегда, независимо от критичности: их нельзя «принять».
    block_secrets: bool = True
    # Как считать UNKNOWN (pip-audit не сообщает уровень).
    unknown_as: Severity = Severity.MEDIUM

    @classmethod
    def load(cls, path: Path) -> Policy:
        raw = tomllib.loads(path.read_text(encoding="utf-8")).get("policy", {})
        policy = cls()
        if "fail_on" in raw:
            policy.fail_on = _severity(raw["fail_on"])
        if "unknown_as" in raw:
            policy.unknown_as = _severity(raw["unknown_as"])
        policy.block_secrets = bool(raw.get("block_secrets", True))
        policy.max_count = {_severity(k): int(v) for k, v in raw.get("max_count", {}).items()}
        return policy

    def effective(self, f: Finding) -> Severity:
        return self.unknown_as if f.severity == Severity.UNKNOWN else f.severity

    def violations(self, findings: list[Finding]) -> list[str]:
        reasons: list[str] = []
        if self.block_secrets:
            secrets = [f for f in findings if f.kind == Kind.SECRET]
            if secrets:
                reasons.append(f"найдено секретов в репозитории: {len(secrets)}")
        blocking = [f for f in findings if f.kind != Kind.SECRET and self.effective(f) >= self.fail_on]
        if blocking:
            reasons.append(f"находок уровня {self.fail_on.name} и выше: {len(blocking)}")
        counts = Counter(self.effective(f) for f in findings)
        for sev, limit in sorted(self.max_count.items()):
            if counts[sev] > limit:
                reasons.append(f"находок уровня {sev.name}: {counts[sev]} (лимит {limit})")
        return reasons


def _severity(value: str) -> Severity:
    sev = Severity.parse(value)
    if sev == Severity.UNKNOWN and value.upper() != "UNKNOWN":
        raise ValueError(f"неизвестный уровень критичности: {value!r}")
    return sev
