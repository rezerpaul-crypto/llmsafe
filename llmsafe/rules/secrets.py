"""Detect likely credentials committed directly to source files."""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Pattern, Tuple

from llmsafe.models import Finding, Severity
from llmsafe.rules.base import line_and_column


@dataclass(frozen=True)
class SecretPattern:
    rule_id: str
    title: str
    severity: Severity
    regex: Pattern[str]
    message: str


PATTERNS: Tuple[SecretPattern, ...] = (
    SecretPattern(
        "SECRET001",
        "OpenAI API key",
        Severity.CRITICAL,
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
        "A value matching an OpenAI API key was found in source control.",
    ),
    SecretPattern(
        "SECRET002",
        "AWS access key",
        Severity.CRITICAL,
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "A value matching an AWS access key ID was found in source control.",
    ),
    SecretPattern(
        "SECRET003",
        "GitHub token",
        Severity.CRITICAL,
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
        "A value matching a GitHub token was found in source control.",
    ),
    SecretPattern(
        "SECRET004",
        "Private key",
        Severity.CRITICAL,
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "A private-key header was found in source control.",
    ),
    SecretPattern(
        "SECRET005",
        "Hard-coded credential",
        Severity.HIGH,
        re.compile(
            r"(?i)\b(?:api[_-]?key|client[_-]?secret|password|access[_-]?token)\b"
            r"\s*[:=]\s*[\"']([^\"']{8,})[\"']"
        ),
        "A credential-like variable contains a literal value.",
    ),
)

PLACEHOLDER_WORDS = (
    "change-me",
    "changeme",
    "dummy",
    "example",
    "placeholder",
    "replace-me",
    "test-only",
    "your-",
)


class SecretRule:
    """Search text files for a focused set of high-confidence secret patterns."""

    def scan(self, path: Path, content: str) -> Iterable[Finding]:
        for pattern in PATTERNS:
            for match in pattern.regex.finditer(content):
                if pattern.rule_id == "SECRET005":
                    value = match.group(1).lower()
                    if any(word in value for word in PLACEHOLDER_WORDS):
                        continue
                line, column = line_and_column(content, match.start())
                yield Finding(
                    rule_id=pattern.rule_id,
                    title=pattern.title,
                    severity=pattern.severity,
                    path=path,
                    line=line,
                    column=column,
                    message=pattern.message,
                    remediation=(
                        "Revoke the credential, remove it from Git history, and load the "
                        "replacement "
                        "from an environment variable or secret manager."
                    ),
                )
