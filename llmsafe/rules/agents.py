"""Structural checks for dangerous agent tools and disabled approval gates."""

import ast
from pathlib import Path
from typing import Dict, Iterable, Optional

from llmsafe.models import Finding, Severity
from llmsafe.rules.ast_helpers import call_name, parse_python

DANGEROUS_TOOL_NAMES = {
    "BashTool",
    "ExecTool",
    "PythonAstREPLTool",
    "PythonREPLTool",
    "ShellTool",
    "TerminalTool",
}
DISABLED_APPROVAL_KEYWORDS = {
    "approval_mode",
    "human_in_the_loop",
    "require_approval",
    "requires_approval",
}


class AgentToolRule:
    """Detect high-impact tools and explicit human-approval bypasses."""

    def scan(self, path: Path, content: str) -> Iterable[Finding]:
        if path.suffix.lower() != ".py":
            return
        tree = parse_python(content)
        if tree is None:
            return
        imports = self._imports(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = self._resolved_call_name(node, imports)
            short_name = name.rsplit(".", 1)[-1] if name else ""
            if short_name in DANGEROUS_TOOL_NAMES:
                yield Finding(
                    "AGENT001",
                    "High-impact tool exposed to an agent",
                    Severity.HIGH,
                    path,
                    node.lineno,
                    node.col_offset + 1,
                    f"{short_name} can execute code or operating-system commands.",
                    "Remove the tool or wrap it with strict arguments, sandboxing, and approval.",
                )
            if self._dangerous_code_enabled(node):
                yield Finding(
                    "AGENT002",
                    "Dangerous agent capability explicitly enabled",
                    Severity.HIGH,
                    path,
                    node.lineno,
                    node.col_offset + 1,
                    "The agent/tool call explicitly enables dangerous code execution.",
                    "Keep dangerous-code flags disabled and expose a narrow typed capability.",
                )
            approval = self._disabled_approval(node)
            if approval:
                yield Finding(
                    "AGENT003",
                    "Human approval gate disabled",
                    Severity.HIGH,
                    path,
                    node.lineno,
                    node.col_offset + 1,
                    f"{approval} disables a human approval boundary for an agent or tool.",
                    "Require approval for high-impact tools and enforce it outside model control.",
                )

    @staticmethod
    def _imports(tree: ast.AST) -> Dict[str, str]:
        imports: Dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports[alias.asname or alias.name.split(".")[0]] = alias.name
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    imports[alias.asname or alias.name] = f"{module}.{alias.name}".strip(".")
        return imports

    @staticmethod
    def _resolved_call_name(node: ast.Call, imports: Dict[str, str]) -> str:
        name = call_name(node) or ""
        first, separator, remainder = name.partition(".")
        resolved = imports.get(first, first)
        return f"{resolved}.{remainder}" if separator else resolved

    @staticmethod
    def _dangerous_code_enabled(node: ast.Call) -> bool:
        for keyword in node.keywords:
            if keyword.arg not in {"allow_dangerous_code", "allow_dangerous_requests"}:
                continue
            return isinstance(keyword.value, ast.Constant) and keyword.value.value is True
        return False

    @staticmethod
    def _disabled_approval(node: ast.Call) -> Optional[str]:
        name = (call_name(node) or "").lower()
        for keyword in node.keywords:
            if keyword.arg not in DISABLED_APPROVAL_KEYWORDS:
                continue
            value = keyword.value
            disabled = isinstance(value, ast.Constant) and (
                value.value is False or str(value.value).lower() in {"never", "none", "off"}
            )
            if disabled and any(marker in name for marker in ("agent", "mcp", "tool", "runner")):
                return keyword.arg
        return None
