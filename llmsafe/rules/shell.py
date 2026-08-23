"""Detect unsafe shell execution in Python applications."""

import ast
from pathlib import Path
from typing import Iterable

from llmsafe.models import Finding, Severity
from llmsafe.rules.ast_helpers import call_name, parse_python


class ShellExecutionRule:
    """Flag shell APIs that can turn model output into command execution."""

    SUBPROCESS_CALLS = {
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "subprocess.run",
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
            if name == "os.system":
                yield Finding(
                    rule_id="SHELL001",
                    title="Shell command execution",
                    severity=Severity.HIGH,
                    path=path,
                    line=node.lineno,
                    column=node.col_offset + 1,
                    message="os.system() executes its argument through a shell.",
                    remediation=(
                        "Use subprocess.run() with an argument list, shell=False, and an "
                        "allow-list."
                    ),
                )
            elif name in self.SUBPROCESS_CALLS and self._uses_shell(node):
                yield Finding(
                    rule_id="SHELL002",
                    title="Subprocess launched through a shell",
                    severity=Severity.HIGH,
                    path=path,
                    line=node.lineno,
                    column=node.col_offset + 1,
                    message=f"{name}() is called with shell=True.",
                    remediation=(
                        "Pass an argument list with shell=False and allow-list commands and "
                        "arguments."
                    ),
                )

    @staticmethod
    def _uses_shell(node: ast.Call) -> bool:
        for keyword in node.keywords:
            if keyword.arg != "shell":
                continue
            return isinstance(keyword.value, ast.Constant) and keyword.value.value is True
        return False
