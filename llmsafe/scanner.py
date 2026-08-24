"""Filesystem traversal and rule orchestration for LLMSafe."""

import fnmatch
import os
import re
from pathlib import Path
from typing import Iterable, Iterator, Optional, Sequence, Tuple

from llmsafe.models import Finding, ScanError, ScanResult
from llmsafe.rules import (
    AgentToolRule,
    DangerousPythonRule,
    DataflowRule,
    DynamicSystemPromptRule,
    MCPConfigRule,
    SecretRule,
    ShellExecutionRule,
)
from llmsafe.rules.base import Rule

DEFAULT_RULES: Tuple[Rule, ...] = (
    SecretRule(),
    DangerousPythonRule(),
    ShellExecutionRule(),
    DynamicSystemPromptRule(),
    DataflowRule(),
    AgentToolRule(),
    MCPConfigRule(),
)

DEFAULT_EXTENSIONS = {
    ".cfg",
    ".env",
    ".ini",
    ".js",
    ".json",
    ".jsx",
    ".md",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}

DEFAULT_IGNORED_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "venv",
}

IGNORE_MARKER = re.compile(r"llmsafe:\s*ignore(?:\[([^\]]+)\])?", re.IGNORECASE)


class Scanner:
    """Scan files with LLMSafe's built-in or user-provided rules."""

    def __init__(
        self,
        rules: Optional[Sequence[Rule]] = None,
        excludes: Sequence[str] = (),
        max_file_size: int = 1_000_000,
        disabled_rules: Sequence[str] = (),
    ) -> None:
        self.rules = tuple(rules) if rules is not None else DEFAULT_RULES
        self.excludes = tuple(excludes)
        self.max_file_size = max_file_size
        self.disabled_rules = {rule_id.upper() for rule_id in disabled_rules}

    def scan(self, targets: Iterable[Path]) -> ScanResult:
        findings = []
        errors = []
        files = []
        scanned_files = 0
        skipped_files = 0
        seen = set()

        for target in targets:
            target_path = Path(target)
            if not target_path.exists():
                errors.append(ScanError(target_path, "Path does not exist"))
                continue
            for path in self._files(target_path):
                try:
                    identity = path.resolve()
                except OSError:
                    identity = path.absolute()
                if identity in seen:
                    continue
                seen.add(identity)
                content = self._read_text(path)
                if content is None:
                    skipped_files += 1
                    continue
                scanned_files += 1
                lines = content.splitlines()
                files.append((path, content, lines))

        for path, content, lines in files:
            for rule in self.rules:
                if callable(getattr(rule, "scan_project", None)):
                    continue
                try:
                    rule_findings = rule.scan(path, content)
                    for finding in rule_findings:
                        if (
                            finding.rule_id.upper() not in self.disabled_rules
                            and not self._ignored(finding, lines)
                        ):
                            findings.append(finding)
                except Exception as exc:  # keep one rule from aborting an entire scan
                    errors.append(ScanError(path, f"{type(rule).__name__}: {exc}"))

        content_by_path = {path: content for path, content, _ in files}
        lines_by_path = {path: lines for path, _, lines in files}
        for rule in self.rules:
            project_scan = getattr(rule, "scan_project", None)
            if not callable(project_scan):
                continue
            try:
                for finding in project_scan(content_by_path):
                    lines = lines_by_path.get(finding.path, ())
                    if (
                        finding.rule_id.upper() not in self.disabled_rules
                        and not self._ignored(finding, lines)
                    ):
                        findings.append(finding)
            except Exception as exc:  # keep one project rule from aborting an entire scan
                errors.append(ScanError(Path("."), f"{type(rule).__name__}: {exc}"))

        findings.sort(
            key=lambda item: (-item.severity.rank, str(item.path), item.line, item.rule_id)
        )
        errors.sort(key=lambda item: str(item.path))
        return ScanResult(tuple(findings), tuple(errors), scanned_files, skipped_files)

    def _files(self, target: Path) -> Iterator[Path]:
        if target.is_symlink():
            return
        if target.is_file():
            if not self._excluded(target) and self._supported(target):
                yield target
            return

        for root, directories, filenames in os.walk(target, followlinks=False):
            root_path = Path(root)
            directories[:] = [
                name
                for name in directories
                if name not in DEFAULT_IGNORED_DIRECTORIES
                and not self._excluded(root_path / name)
            ]
            for filename in sorted(filenames):
                path = root_path / filename
                if (
                    not path.is_symlink()
                    and not self._excluded(path)
                    and self._supported(path)
                ):
                    yield path

    def _excluded(self, path: Path) -> bool:
        rendered = path.as_posix()
        return any(
            fnmatch.fnmatch(rendered, pattern)
            or fnmatch.fnmatch(path.name, pattern)
            or fnmatch.fnmatch(rendered, f"*/{pattern}")
            for pattern in self.excludes
        )

    @staticmethod
    def _supported(path: Path) -> bool:
        return path.suffix.lower() in DEFAULT_EXTENSIONS or path.name.lower() in {
            ".env",
            "dockerfile",
        }

    def _read_text(self, path: Path) -> Optional[str]:
        try:
            with path.open("rb") as handle:
                raw = handle.read(self.max_file_size + 1)
        except (OSError, PermissionError):
            return None
        if len(raw) > self.max_file_size or b"\x00" in raw:
            return None
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return None

    @staticmethod
    def _ignored(finding: Finding, lines: Sequence[str]) -> bool:
        for line_number in (finding.line, finding.line - 1):
            if line_number < 1 or line_number > len(lines):
                continue
            marker = IGNORE_MARKER.search(lines[line_number - 1])
            if marker is None:
                continue
            selected = marker.group(1)
            if selected is None:
                return True
            rule_ids = {value.strip().upper() for value in selected.split(",")}
            if finding.rule_id.upper() in rule_ids:
                return True
        return False
