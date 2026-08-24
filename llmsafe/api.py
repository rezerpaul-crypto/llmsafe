"""Small public Python API for organization-specific LLMSafe rules."""

from pathlib import Path
from typing import Iterable, Sequence, Tuple

from llmsafe.models import Evidence, Finding, ScanResult, Severity
from llmsafe.rules.base import Rule
from llmsafe.scanner import DEFAULT_RULES, Scanner


def built_in_rules() -> Tuple[Rule, ...]:
    """Return LLMSafe's built-in rule set in deterministic execution order."""

    return tuple(DEFAULT_RULES)


def scan_paths(
    paths: Iterable[Path],
    *,
    extra_rules: Sequence[Rule] = (),
    excludes: Sequence[str] = (),
    max_file_size: int = 1_000_000,
    disabled_rules: Sequence[str] = (),
) -> ScanResult:
    """Scan paths with built-ins plus explicitly supplied trusted rules."""

    rules = (*built_in_rules(), *extra_rules)
    scanner = Scanner(
        rules=rules,
        excludes=excludes,
        max_file_size=max_file_size,
        disabled_rules=disabled_rules,
    )
    return scanner.scan(paths)


__all__ = [
    "Evidence",
    "Finding",
    "Rule",
    "ScanResult",
    "Severity",
    "built_in_rules",
    "scan_paths",
]
