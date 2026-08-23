"""Detect dangerous dynamic execution and deserialization in Python."""

import ast
from pathlib import Path
from typing import Iterable

from llmsafe.models import Finding, Severity
from llmsafe.rules.ast_helpers import call_name, parse_python


class DangerousPythonRule:
    """Flag primitives that commonly turn untrusted model output into code."""

    DANGEROUS_CALLS = {
        "eval": (
            "PY001",
            "Dynamic code evaluation",
            Severity.HIGH,
            "eval() executes a string as Python code.",
            "Parse the expected data format explicitly; never pass model or user output to eval().",
        ),
        "exec": (
            "PY002",
            "Dynamic code execution",
            Severity.CRITICAL,
            "exec() executes arbitrary Python statements.",
            "Replace dynamic execution with an allow-listed command or structured operation.",
        ),
        "pickle.load": (
            "PY003",
            "Unsafe deserialization",
            Severity.HIGH,
            "pickle.load() can execute code while deserializing attacker-controlled data.",
            "Use JSON or another non-executable format and validate the decoded schema.",
        ),
        "pickle.loads": (
            "PY003",
            "Unsafe deserialization",
            Severity.HIGH,
            "pickle.loads() can execute code while deserializing attacker-controlled data.",
            "Use JSON or another non-executable format and validate the decoded schema.",
        ),
        "yaml.load": (
            "PY004",
            "Potentially unsafe YAML load",
            Severity.MEDIUM,
            "yaml.load() may instantiate unsafe Python objects, depending on its loader.",
            "Use yaml.safe_load() for data-only YAML.",
        ),
    }

    def scan(self, path: Path, content: str) -> Iterable[Finding]:
        if path.suffix.lower() != ".py":
            return
        tree = parse_python(content)
        if tree is None:
            return
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = call_name(node)
            if name not in self.DANGEROUS_CALLS:
                continue
            rule_id, title, severity, message, remediation = self.DANGEROUS_CALLS[name]
            yield Finding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                path=path,
                line=node.lineno,
                column=node.col_offset + 1,
                message=message,
                remediation=remediation,
            )
