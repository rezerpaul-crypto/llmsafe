"""Deterministic baselines for incremental LLMSafe adoption."""

import hashlib
import json
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

from llmsafe import __version__
from llmsafe.models import Finding, ScanResult

BASELINE_SCHEMA_VERSION = 1
MAX_BASELINE_SIZE = 10_000_000


class BaselineError(ValueError):
    """Raised when a baseline cannot be read, validated, or written."""


@dataclass(frozen=True)
class Baseline:
    """Validated collection of finding fingerprints."""

    fingerprints: Tuple[str, ...]


def finding_fingerprint(finding: Finding, root: Optional[Path] = None) -> str:
    """Return a stable identity that tolerates line movement within a file."""

    identity = "\0".join(
        (
            finding.rule_id,
            _relative_path(finding.path, root or Path.cwd()),
            finding.title,
            finding.message.split(" Source:", 1)[0],
        )
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def load_baseline(path: Path) -> Baseline:
    """Load and strictly validate a baseline JSON document."""

    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_BASELINE_SIZE + 1)
        if len(raw) > MAX_BASELINE_SIZE:
            raise BaselineError(f"Baseline exceeds {MAX_BASELINE_SIZE} bytes: {path}")
        document = json.loads(raw.decode("utf-8"))
    except BaselineError:
        raise
    except FileNotFoundError as exc:
        raise BaselineError(f"Baseline file does not exist: {path}") from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BaselineError(f"Cannot read baseline {path}: {exc}") from exc

    if not isinstance(document, dict):
        raise BaselineError(f"Baseline {path} must be a JSON object")
    if document.get("schema_version") != BASELINE_SCHEMA_VERSION:
        raise BaselineError(
            f"Baseline {path} must use schema_version {BASELINE_SCHEMA_VERSION}"
        )
    entries = document.get("findings")
    if not isinstance(entries, list):
        raise BaselineError(f"findings in {path} must be an array")

    fingerprints = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise BaselineError(f"findings[{index}] in {path} must be an object")
        fingerprint = entry.get("fingerprint")
        if not _valid_fingerprint(fingerprint):
            raise BaselineError(
                f"findings[{index}].fingerprint in {path} must be a SHA-256 hex digest"
            )
        if not isinstance(entry.get("rule_id"), str) or not isinstance(entry.get("path"), str):
            raise BaselineError(f"findings[{index}] in {path} requires rule_id and path strings")
        line = entry.get("line")
        if not isinstance(line, int) or isinstance(line, bool) or line < 1:
            raise BaselineError(f"findings[{index}].line in {path} must be a positive integer")
        fingerprints.append(fingerprint)
    return Baseline(tuple(fingerprints))


def write_baseline(
    path: Path, findings: Iterable[Finding], root: Optional[Path] = None
) -> int:
    """Write a deterministic baseline and return the number of recorded findings."""

    selected_root = root or Path.cwd()
    entries = [
        {
            "fingerprint": finding_fingerprint(finding, selected_root),
            "line": finding.line,
            "path": _relative_path(finding.path, selected_root),
            "rule_id": finding.rule_id,
        }
        for finding in findings
    ]
    entries.sort(key=lambda entry: (entry["path"], entry["line"], entry["rule_id"]))
    document: Dict[str, Any] = {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "generated_by": {"name": "LLMSafe", "version": __version__},
        "findings": entries,
    }
    temporary_path = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(json.dumps(document, indent=2, sort_keys=True) + "\n")
        temporary_path.replace(path)
    except (OSError, UnicodeError) as exc:
        raise BaselineError(f"Cannot write baseline {path}: {exc}") from exc
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
    return len(entries)


def apply_baseline(
    result: ScanResult, baseline: Baseline, root: Optional[Path] = None
) -> ScanResult:
    """Remove only the number of findings explicitly represented by a baseline."""

    remaining = Counter(baseline.fingerprints)
    selected_root = root or Path.cwd()
    active = []
    matched = 0
    for finding in result.findings:
        fingerprint = finding_fingerprint(finding, selected_root)
        if remaining[fingerprint] > 0:
            remaining[fingerprint] -= 1
            matched += 1
        else:
            active.append(finding)
    return ScanResult(
        findings=tuple(active),
        errors=result.errors,
        scanned_files=result.scanned_files,
        skipped_files=result.skipped_files,
        baseline_findings=result.baseline_findings + matched,
    )


def _relative_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return path.as_posix()


def _valid_fingerprint(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(character in "0123456789abcdef" for character in value)
