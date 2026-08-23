"""Shared data models used by rules, the scanner, and output renderers."""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Tuple


class Severity(str, Enum):
    """Finding severity in ascending order of impact."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls(value.lower())
        except ValueError as exc:
            choices = ", ".join(item.value for item in cls)
            raise ValueError(f"Unknown severity {value!r}; choose one of: {choices}") from exc


@dataclass(frozen=True)
class Finding:
    """A single security issue reported by a rule."""

    rule_id: str
    title: str
    severity: Severity
    path: Path
    line: int
    column: int
    message: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "path": str(self.path),
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "remediation": self.remediation,
        }


@dataclass(frozen=True)
class ScanError:
    """A non-fatal problem encountered while scanning a file."""

    path: Path
    message: str

    def to_dict(self) -> Dict[str, str]:
        return {"path": str(self.path), "message": self.message}


@dataclass(frozen=True)
class ScanResult:
    """Aggregate result returned by :class:`llmsafe.scanner.Scanner`."""

    findings: Tuple[Finding, ...]
    errors: Tuple[ScanError, ...]
    scanned_files: int
    skipped_files: int

    def has_findings_at(self, minimum: Severity) -> bool:
        return any(finding.severity.rank >= minimum.rank for finding in self.findings)
