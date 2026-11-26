"""Единая модель находки, к которой приводятся отчёты всех сканеров."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Уровни критичности. Порядок важен: сравниваем как числа."""

    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | None) -> Severity:
        """Приводит обозначения разных сканеров к одной шкале."""
        if not value:
            return cls.UNKNOWN
        aliases = {
            "NEGLIGIBLE": cls.LOW,
            "INFO": cls.LOW,
            "WARNING": cls.MEDIUM,
            "MODERATE": cls.MEDIUM,
            "ERROR": cls.HIGH,
            "IMPORTANT": cls.HIGH,
        }
        key = value.strip().upper()
        if key in aliases:
            return aliases[key]
        try:
            return cls[key]
        except KeyError:
            return cls.UNKNOWN


def normalize_package(name: str | None) -> str:
    """Имя пакета по PEP 503: Trivy пишет "PyYAML", pip-audit — "pyyaml"."""
    return re.sub(r"[-_.]+", "-", name or "").lower()


class Kind:
    """Категория находки (строковые константы, чтобы легко сериализовать)."""

    DEPENDENCY = "dependency"  # уязвимая библиотека (SCA)
    CODE = "code"  # проблема в исходном коде (SAST)
    CONFIG = "config"  # ошибка конфигурации (Dockerfile, IaC)
    SECRET = "secret"  # noqa: S105  # nosec B105 — название категории, а не пароль


@dataclass
class Finding:
    tool: str
    kind: str
    rule_id: str
    severity: Severity
    title: str
    path: str = ""
    line: int | None = None
    package: str | None = None
    version: str | None = None
    fixed_version: str | None = None
    aliases: set[str] = field(default_factory=set)
    url: str | None = None
    sources: set[str] = field(default_factory=set)

    fingerprint: str = field(init=False)
    # Все отпечатки, слившиеся в эту находку: baseline совпадает с любым из них.
    fingerprints: set[str] = field(init=False)

    def __post_init__(self) -> None:
        self.sources.add(self.tool)
        # Сканеры пишут пути по-разному: "./app.py" и "app.py" — один и тот же файл.
        self.path = self.path.removeprefix("./").replace("\\", "/")
        # Отпечаток считается один раз: после слияния дубликатов набор алиасов растёт,
        # и пересчёт мог бы дать другое значение — baseline перестал бы совпадать.
        self.fingerprint = self._compute_fingerprint()
        self.fingerprints = {self.fingerprint}

    @property
    def vuln_id(self) -> str:
        """Каноничный идентификатор уязвимости: CVE в приоритете, иначе rule_id."""
        ids = {self.rule_id, *self.aliases}
        cves = sorted(i for i in ids if i.upper().startswith("CVE-"))
        return cves[0] if cves else self.rule_id

    @property
    def cwe(self) -> str | None:
        cwes = sorted(a for a in self.aliases if a.upper().startswith("CWE-"))
        return cwes[0] if cwes else None

    def _compute_fingerprint(self) -> str:
        """Стабильный отпечаток для дедупликации и baseline.

        Для зависимостей не зависит от сканера: одна и та же CVE в одной версии
        пакета от Trivy и pip-audit даёт одинаковый отпечаток. Номер строки в код
        не входит — иначе любая правка выше по файлу «создавала» бы новую находку.
        """
        if self.kind == Kind.DEPENDENCY:
            key = f"dep|{normalize_package(self.package)}|{self.version}|{self.vuln_id}"
        else:
            key = f"{self.kind}|{self.tool}|{self.rule_id}|{self.path}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def merge(self, other: Finding) -> None:
        """Объединяет дубликат: берём максимальную критичность и всю известную информацию."""
        # Заголовок — от сканера, который оценил риск выше (pip-audit критичность не даёт,
        # а его «заголовок» — это начало длинного описания).
        if other.severity > self.severity:
            self.title = other.title
        self.severity = max(self.severity, other.severity)
        self.aliases |= other.aliases | {other.rule_id}
        self.aliases.discard(self.rule_id)
        self.sources |= other.sources
        self.fingerprints |= other.fingerprints
        self.fixed_version = self.fixed_version or other.fixed_version
        self.url = self.url or other.url
        if self.line is None:
            self.line = other.line
