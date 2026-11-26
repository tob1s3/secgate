"""Baseline — список принятых рисков.

Каждое исключение обязано иметь причину и дату истечения: «временно» не должно
становиться «навсегда». Просроченное исключение перестаёт действовать, и находка
снова блокирует сборку.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from .models import Finding, Kind

MAX_DAYS = 180  # дольше полугода риск не принимаем без пересмотра


class BaselineError(ValueError):
    pass


@dataclass(frozen=True)
class Exception_:
    fingerprint: str
    reason: str
    expires: date
    owner: str = ""

    def active(self, today: date) -> bool:
        return today <= self.expires


@dataclass
class Baseline:
    entries: dict[str, Exception_]

    @classmethod
    def empty(cls) -> Baseline:
        return cls({})

    @classmethod
    def load(cls, path: Path, today: date | None = None) -> Baseline:
        today = today or date.today()
        raw = json.loads(path.read_text(encoding="utf-8"))
        entries: dict[str, Exception_] = {}
        for i, item in enumerate(raw.get("exceptions", [])):
            where = f"{path}: exceptions[{i}]"
            for required in ("fingerprint", "reason", "expires"):
                if not item.get(required):
                    raise BaselineError(f"{where}: не заполнено поле {required!r}")
            try:
                expires = date.fromisoformat(item["expires"])
            except ValueError:
                raise BaselineError(f"{where}: дата {item['expires']!r} не в формате ГГГГ-ММ-ДД") from None
            if (expires - today).days > MAX_DAYS:
                raise BaselineError(f"{where}: срок исключения больше {MAX_DAYS} дней")
            entries[item["fingerprint"]] = Exception_(
                fingerprint=item["fingerprint"],
                reason=item["reason"],
                expires=expires,
                owner=item.get("owner", ""),
            )
        return cls(entries)

    def split(
        self, findings: list[Finding], today: date | None = None
    ) -> tuple[list[Finding], list[Finding], list[Exception_]]:
        """Возвращает (новые, принятые, просроченные исключения, которые снова сработали)."""
        today = today or date.today()
        new, accepted, expired = [], [], []
        for f in findings:
            exc = self._match(f)
            # Утёкший секрет нельзя «принять» — его нужно отозвать и удалить из истории.
            if exc and exc.active(today) and f.kind != Kind.SECRET:
                accepted.append(f)
            else:
                new.append(f)
                if exc:
                    expired.append(exc)
        return new, accepted, expired

    def _match(self, f: Finding) -> Exception_ | None:
        for fp in [f.fingerprint, *sorted(f.fingerprints - {f.fingerprint})]:
            if fp in self.entries:
                return self.entries[fp]
        return None

    def unused(self, findings: list[Finding]) -> list[Exception_]:
        """Исключения, которым больше нет соответствующих находок — их пора удалить."""
        present = set().union(*(f.fingerprints for f in findings)) if findings else set()
        return [e for k, e in self.entries.items() if k not in present]
