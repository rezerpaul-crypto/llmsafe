"""Worked example: detect an agent created with literal debug mode enabled."""

import ast
from pathlib import Path
from typing import Iterable

from llmsafe.models import Finding, Severity
from llmsafe.rules.ast_helpers import call_name, parse_python


class DebugAgentRule:
    """Report explicit ``Agent(debug=True)`` construction."""

    rule_id = "EXAMPLE001"

    def scan(self, path: Path, content: str) -> Iterable[Finding]:
        if path.suffix.lower() != ".py":
            return

        tree = parse_python(content)
        if tree is None:
            return

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = call_name(node) or ""
            if name.rsplit(".", 1)[-1] != "Agent":
                continue
            if not self._literal_debug_enabled(node):
                continue
            yield Finding(
                self.rule_id,
                "Agent debug mode enabled",
                Severity.MEDIUM,
                path,
                node.lineno,
                node.col_offset + 1,
                "The agent is created with debug=True, which can expose sensitive execution data.",
                "Disable debug mode outside isolated development and sanitize diagnostic output.",
            )

    @staticmethod
    def _literal_debug_enabled(node: ast.Call) -> bool:
        return any(
            keyword.arg == "debug"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        )
