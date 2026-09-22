"""Detect dangerous dynamic execution and deserialization in Python."""

import ast
from pathlib import Path
from typing import Dict, Iterable, Optional, Set, Tuple

from llmsafe.models import Finding, Severity
from llmsafe.rules.ast_helpers import call_name, parse_python


PY004 = (
    "PY004",
    "Potentially unsafe YAML load",
    Severity.MEDIUM,
    "YAML is loaded with a constructor that can instantiate Python objects.",
    "Use yaml.safe_load() or yaml.load(..., Loader=yaml.SafeLoader) for data-only YAML.",
)

UNSAFE_YAML_FUNCTIONS = {"load", "unsafe_load", "full_load", "load_all"}
SAFE_YAML_FUNCTIONS = {"safe_load", "safe_load_all"}
UNSAFE_LOADERS = {
    "Loader",
    "FullLoader",
    "UnsafeLoader",
    "CLoader",
    "CFullLoader",
    "CUnsafeLoader",
}
SAFE_LOADERS = {"SafeLoader", "CSafeLoader"}


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
    }

    def scan(self, path: Path, content: str) -> Iterable[Finding]:
        if path.suffix.lower() != ".py":
            return
        tree = parse_python(content)
        if tree is None:
            return

        yaml_modules, yaml_funcs, loader_aliases = _yaml_bindings(tree)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = call_name(node)

            if name in self.DANGEROUS_CALLS:
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
                continue

            if _is_unsafe_yaml_call(node, name, yaml_modules, yaml_funcs, loader_aliases):
                rule_id, title, severity, message, remediation = PY004
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


def _yaml_bindings(
    tree: ast.AST,
) -> Tuple[Set[str], Dict[str, str], Dict[str, str]]:
    """Resolve ``yaml`` module aliases, function aliases, and loader aliases."""

    yaml_modules: Set[str] = {"yaml"}
    yaml_funcs: Dict[str, str] = {}
    loader_aliases: Dict[str, str] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "yaml":
                    yaml_modules.add(alias.asname or "yaml")
        elif isinstance(node, ast.ImportFrom) and node.module == "yaml":
            for alias in node.names:
                local = alias.asname or alias.name
                if alias.name in UNSAFE_YAML_FUNCTIONS or alias.name in SAFE_YAML_FUNCTIONS:
                    yaml_funcs[local] = alias.name
                if alias.name in UNSAFE_LOADERS or alias.name in SAFE_LOADERS:
                    loader_aliases[local] = alias.name
    return yaml_modules, yaml_funcs, loader_aliases


def _is_unsafe_yaml_call(
    node: ast.Call,
    name: Optional[str],
    yaml_modules: Set[str],
    yaml_funcs: Dict[str, str],
    loader_aliases: Dict[str, str],
) -> bool:
    if name is None:
        return False

    function = None
    if name in yaml_funcs:
        function = yaml_funcs[name]
    else:
        parts = name.split(".")
        if len(parts) == 2 and parts[0] in yaml_modules:
            function = parts[1]

    if function is None:
        return False
    if function in SAFE_YAML_FUNCTIONS:
        return False
    if function not in UNSAFE_YAML_FUNCTIONS:
        return False
    if function in {"load", "load_all"} and _uses_safe_loader(
        node, yaml_modules, loader_aliases
    ):
        return False
    return True


def _uses_safe_loader(
    node: ast.Call,
    yaml_modules: Set[str],
    loader_aliases: Dict[str, str],
) -> bool:
    loader_node = None
    for keyword in node.keywords:
        if keyword.arg == "Loader":
            loader_node = keyword.value
            break
    if loader_node is None and len(node.args) >= 2:
        loader_node = node.args[1]
    if loader_node is None:
        return False
    loader_name = _loader_name(loader_node, yaml_modules, loader_aliases)
    return loader_name in SAFE_LOADERS


def _loader_name(
    node: ast.AST,
    yaml_modules: Set[str],
    loader_aliases: Dict[str, str],
) -> Optional[str]:
    if isinstance(node, ast.Name):
        if node.id in loader_aliases:
            return loader_aliases[node.id]
        if node.id in SAFE_LOADERS or node.id in UNSAFE_LOADERS:
            return node.id
        return None
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        if node.value.id in yaml_modules:
            return node.attr
    return None
