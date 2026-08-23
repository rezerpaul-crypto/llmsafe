"""Repository policy loading for LLMSafe."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, FrozenSet, Optional, Tuple

try:
    import tomllib
except ImportError:  # pragma: no cover - exercised on Python 3.9 in CI
    import tomli as tomllib

from llmsafe.models import Severity


class ConfigError(ValueError):
    """Raised when a policy file is missing or invalid."""


@dataclass(frozen=True)
class Config:
    """Validated scanner settings from a repository policy."""

    excludes: Tuple[str, ...] = ()
    fail_on: Severity = Severity.HIGH
    max_file_size: int = 1_000_000
    disabled_rules: FrozenSet[str] = frozenset()
    baseline: Optional[Path] = None
    source: Optional[Path] = None


ALLOWED_KEYS = {"baseline", "exclude", "fail_on", "max_file_size", "disabled_rules"}


def discover_config(start: Path) -> Optional[Path]:
    """Find the closest LLMSafe policy, stopping at the filesystem root."""

    current = start.resolve()
    if current.is_file():
        current = current.parent
    for directory in (current, *current.parents):
        dedicated = directory / ".llmsafe.toml"
        if dedicated.is_file():
            return dedicated
        pyproject = directory / "pyproject.toml"
        if pyproject.is_file() and _contains_pyproject_policy(pyproject):
            return pyproject
    return None


def load_config(path: Optional[Path] = None, start: Optional[Path] = None) -> Config:
    """Load a dedicated policy or ``[tool.llmsafe]`` from ``pyproject.toml``."""

    selected = path or discover_config(start or Path.cwd())
    if selected is None:
        return Config()
    if not selected.is_file():
        raise ConfigError(f"Configuration file does not exist: {selected}")
    try:
        with selected.open("rb") as handle:
            document = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Invalid TOML in {selected}: {exc}") from exc
    raw = _policy_table(selected, document)
    return _validate(selected, raw)


def _contains_pyproject_policy(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return False
    return isinstance(document.get("tool", {}).get("llmsafe"), dict)


def _policy_table(path: Path, document: Dict[str, Any]) -> Dict[str, Any]:
    if path.name == "pyproject.toml":
        raw = document.get("tool", {}).get("llmsafe")
    else:
        raw = document.get("llmsafe")
    if not isinstance(raw, dict):
        section = "[tool.llmsafe]" if path.name == "pyproject.toml" else "[llmsafe]"
        raise ConfigError(f"{path} must contain a {section} table")
    return raw


def _validate(path: Path, raw: Dict[str, Any]) -> Config:
    unknown = sorted(set(raw) - ALLOWED_KEYS)
    if unknown:
        raise ConfigError(f"Unknown setting(s) in {path}: {', '.join(unknown)}")

    excludes = _string_list(path, "exclude", raw.get("exclude", []))
    disabled = _string_list(path, "disabled_rules", raw.get("disabled_rules", []))
    fail_on = raw.get("fail_on", Severity.HIGH.value)
    if not isinstance(fail_on, str):
        raise ConfigError(f"fail_on in {path} must be a severity string")
    try:
        severity = Severity.parse(fail_on)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc

    max_file_size = raw.get("max_file_size", 1_000_000)
    if not isinstance(max_file_size, int) or isinstance(max_file_size, bool) or max_file_size < 1:
        raise ConfigError(f"max_file_size in {path} must be a positive integer")
    normalized_rules = frozenset(rule_id.upper() for rule_id in disabled)
    baseline_value = raw.get("baseline")
    if baseline_value is not None and (
        not isinstance(baseline_value, str) or not baseline_value.strip()
    ):
        raise ConfigError(f"baseline in {path} must be a non-empty path string")
    baseline = (path.parent / baseline_value).resolve() if baseline_value else None
    return Config(
        excludes=excludes,
        fail_on=severity,
        max_file_size=max_file_size,
        disabled_rules=normalized_rules,
        baseline=baseline,
        source=path,
    )


def _string_list(path: Path, name: str, value: Any) -> Tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{name} in {path} must be an array of strings")
    return tuple(value)
