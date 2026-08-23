"""Small AST helpers shared by Python-specific rules."""

import ast
from typing import Optional


def call_name(node: ast.Call) -> Optional[str]:
    """Return a dotted name for simple function and method calls."""

    parts = []
    current = node.func
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def parse_python(content: str) -> Optional[ast.AST]:
    """Parse Python, returning ``None`` for incomplete or invalid source."""

    try:
        return ast.parse(content)
    except (SyntaxError, ValueError):
        return None
