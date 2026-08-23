"""Rules for unsafe mixing of trusted and untrusted prompt content."""

import ast
from pathlib import Path
from typing import Iterable, Optional

from llmsafe.models import Finding, Severity
from llmsafe.rules.ast_helpers import parse_python

TRUSTED_PROMPT_NAMES = {
    "developer_message",
    "developer_prompt",
    "system_instruction",
    "system_instructions",
    "system_message",
    "system_prompt",
}


def _target_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id.lower()
    if isinstance(node, ast.Attribute):
        return node.attr.lower()
    return None


def _is_dynamic_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(value, ast.FormattedValue) for value in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return not (isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return node.func.attr in {"format", "format_map"}
    return False


class DynamicSystemPromptRule:
    """Find direct interpolation into privileged system/developer instructions."""

    def scan(self, path: Path, content: str) -> Iterable[Finding]:
        if path.suffix.lower() != ".py":
            return
        tree = parse_python(content)
        if tree is None:
            return

        seen = set()
        for node in ast.walk(tree):
            value: Optional[ast.AST] = None
            name: Optional[str] = None
            if isinstance(node, ast.Assign):
                value = node.value
                if len(node.targets) == 1:
                    name = _target_name(node.targets[0])
            elif isinstance(node, ast.AnnAssign):
                value = node.value
                name = _target_name(node.target)
            elif isinstance(node, ast.keyword):
                value = node.value
                name = node.arg.lower() if node.arg else None

            if name not in TRUSTED_PROMPT_NAMES or value is None or not _is_dynamic_string(value):
                continue
            location = (getattr(node, "lineno", 1), getattr(node, "col_offset", 0) + 1)
            if location in seen:
                continue
            seen.add(location)
            yield Finding(
                rule_id="LLM001",
                title="Dynamic data in privileged prompt",
                severity=Severity.HIGH,
                path=path,
                line=location[0],
                column=location[1],
                message=(
                    f"{name} mixes dynamic data directly into a trusted instruction channel."
                ),
                remediation=(
                    "Keep system/developer instructions static. Put user-controlled content in a "
                    "separate user message and validate data before tool use."
                ),
            )
