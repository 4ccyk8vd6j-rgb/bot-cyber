"""Modèle de données pour les findings (résultats d'analyse)."""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Iterable


class Severity(str, Enum):
    """Niveaux de sévérité, alignés sur les conventions CVSS."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        order = {
            "info": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }
        return order[self.value]

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        """Convertit un score CVSS (0-10) en sévérité."""
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


@dataclass
class Finding:
    """Un résultat d'analyse unitaire."""

    title: str
    severity: Severity
    target: str
    module: str
    description: str = ""
    evidence: str = ""
    recommendation: str = ""
    references: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


class FindingsCollection:
    """Agrège des findings et fournit tri / statistiques."""

    def __init__(self) -> None:
        self._items: list[Finding] = []

    def add(self, finding: Finding) -> None:
        self._items.append(finding)

    def extend(self, findings: Iterable[Finding]) -> None:
        for f in findings:
            self.add(f)

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self):
        return iter(self._items)

    @property
    def items(self) -> list[Finding]:
        """Findings triés par sévérité décroissante puis par module."""
        return sorted(
            self._items,
            key=lambda f: (-f.severity.rank, f.module, f.title),
        )

    def by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self._items:
            counts[f.severity.value] += 1
        return counts

    def highest_severity(self) -> Severity:
        if not self._items:
            return Severity.INFO
        return max((f.severity for f in self._items), key=lambda s: s.rank)

    def to_list(self) -> list[dict[str, Any]]:
        return [f.to_dict() for f in self.items]
