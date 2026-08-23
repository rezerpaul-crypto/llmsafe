"""Intra-procedural taint analysis for AI and agent trust boundaries."""

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from llmsafe.models import Evidence, Finding, Severity
from llmsafe.rules.ast_helpers import call_name, parse_python

MODEL_PARAMETER = re.compile(
    r"^(?:(?:agent|assistant|llm|model)_(?:output|response|result|text)|completion)$",
    re.IGNORECASE,
)
USER_PARAMETER = re.compile(
    r"^(?:command|input|payload|prompt|query|request|user(?:_.*)?|"
    r".*_(?:command|input|payload|query|request))$",
    re.IGNORECASE,
)

MODEL_CALL_MARKERS = (
    ".chat.completions.create",
    ".messages.create",
    ".responses.create",
    ".generate",
    ".invoke",
    ".predict",
)
USER_CALLS = {
    "input",
    "request.get_json",
}
USER_ATTRIBUTES = {"args", "data", "form", "json", "query_params"}


@dataclass(frozen=True)
class TaintSource:
    """Origin of data that crosses an application trust boundary."""

    kind: str
    label: str
    line: int
    column: int


Taint = Set[TaintSource]
Environment = Dict[str, Taint]


@dataclass(frozen=True)
class Sink:
    rule_id: str
    title: str
    severity: Severity
    message: str
    remediation: str


CODE_SINK = Sink(
    "FLOW001",
    "Untrusted data reaches code execution",
    Severity.CRITICAL,
    "Untrusted or model-controlled data flows into {sink}().",
    "Replace dynamic execution with a typed parser and an allow-listed operation.",
)
SHELL_SINK = Sink(
    "FLOW002",
    "Untrusted data reaches process execution",
    Severity.CRITICAL,
    "Untrusted or model-controlled data flows into {sink}().",
    "Map requests to fixed executables and validated arguments; do not execute generated text.",
)
SQL_SINK = Sink(
    "FLOW003",
    "Untrusted data reaches a SQL query",
    Severity.HIGH,
    "Untrusted or model-controlled data changes the SQL passed to {sink}().",
    "Use a constant query with bound parameters and allow-list dynamic identifiers.",
)
URL_SINK = Sink(
    "FLOW004",
    "Untrusted data controls an outbound URL",
    Severity.HIGH,
    "Untrusted or model-controlled data controls the URL passed to {sink}().",
    "Allow-list schemes and hosts, resolve DNS safely, and block private network ranges.",
)
TOOL_SINK = Sink(
    "FLOW005",
    "Untrusted data controls tool dispatch",
    Severity.HIGH,
    "Untrusted or model-controlled data selects a callable dynamically.",
    "Resolve tool names through a fixed allow-list and enforce per-tool authorization.",
)

SUBPROCESS_CALLS = {
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
    "subprocess.run",
}
HTTP_CALL_SUFFIXES = {
    ".delete",
    ".get",
    ".head",
    ".patch",
    ".post",
    ".put",
    ".request",
}
HTTP_CLIENT_PREFIXES = ("httpx", "requests", "urllib3")


class DataflowRule:
    """Trace trust-boundary data to security-sensitive operations."""

    def scan(self, path: Path, content: str) -> Iterable[Finding]:
        if path.suffix.lower() != ".py":
            return
        tree = parse_python(content)
        if tree is None:
            return

        analyzer = _ScopeAnalyzer(path)
        analyzer.analyze_scope(tree.body, {})  # type: ignore[attr-defined]
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                environment = analyzer.parameter_environment(node.args)
                analyzer.analyze_scope(node.body, environment)
        yield from analyzer.findings


class _ScopeAnalyzer:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: List[Finding] = []
        self._seen: Set[Tuple[str, int, int]] = set()

    def parameter_environment(self, arguments: ast.arguments) -> Environment:
        environment: Environment = {}
        all_arguments = (
            list(arguments.posonlyargs) + list(arguments.args) + list(arguments.kwonlyargs)
        )
        if arguments.vararg:
            all_arguments.append(arguments.vararg)
        if arguments.kwarg:
            all_arguments.append(arguments.kwarg)
        for argument in all_arguments:
            source = self._named_source(argument.arg, argument)
            if source:
                environment[argument.arg] = {source}
        return environment

    def analyze_scope(
        self, statements: Sequence[ast.stmt], environment: Environment
    ) -> Environment:
        current = self._copy_environment(environment)
        for statement in statements:
            current = self._statement(statement, current)
        return current

    def _statement(self, statement: ast.stmt, environment: Environment) -> Environment:
        current = self._copy_environment(environment)
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return current
        if isinstance(statement, ast.Assign):
            taint = self._expression(statement.value, current)
            for target in statement.targets:
                self._assign(target, taint, current)
        elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
            self._assign(statement.target, self._expression(statement.value, current), current)
        elif isinstance(statement, ast.AugAssign):
            taint = self._expression(statement.value, current) | self._expression(
                statement.target, current
            )
            self._assign(statement.target, taint, current)
        elif isinstance(statement, ast.Expr):
            self._expression(statement.value, current)
        elif isinstance(statement, (ast.Return, ast.Raise)):
            value = getattr(statement, "value", None) or getattr(statement, "exc", None)
            if value is not None:
                self._expression(value, current)
        elif isinstance(statement, ast.If):
            self._expression(statement.test, current)
            left = self.analyze_scope(statement.body, current)
            right = self.analyze_scope(statement.orelse, current)
            current = self._merge_environments(left, right)
        elif isinstance(statement, (ast.For, ast.AsyncFor)):
            iter_taint = self._expression(statement.iter, current)
            loop_environment = self._copy_environment(current)
            self._assign(statement.target, iter_taint, loop_environment)
            body = self.analyze_scope(statement.body, loop_environment)
            otherwise = self.analyze_scope(statement.orelse, current)
            current = self._merge_environments(current, body, otherwise)
        elif isinstance(statement, ast.While):
            self._expression(statement.test, current)
            body = self.analyze_scope(statement.body, current)
            otherwise = self.analyze_scope(statement.orelse, current)
            current = self._merge_environments(current, body, otherwise)
        elif isinstance(statement, ast.Try):
            branches = [self.analyze_scope(statement.body, current)]
            branches.extend(
                self.analyze_scope(handler.body, current) for handler in statement.handlers
            )
            branches.append(self.analyze_scope(statement.orelse, current))
            current = self._merge_environments(current, *branches)
            current = self.analyze_scope(statement.finalbody, current)
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            for item in statement.items:
                taint = self._expression(item.context_expr, current)
                if item.optional_vars:
                    self._assign(item.optional_vars, taint, current)
            current = self.analyze_scope(statement.body, current)
        else:
            for child in ast.iter_child_nodes(statement):
                if isinstance(child, ast.expr):
                    self._expression(child, current)
        return current

    def _expression(self, node: ast.AST, environment: Environment) -> Taint:
        if isinstance(node, ast.Name):
            return set(environment.get(node.id, set()))
        if isinstance(node, ast.Constant):
            return set()
        if isinstance(node, ast.Attribute):
            taint = self._expression(node.value, environment)
            if node.attr in USER_ATTRIBUTES and self._root_name(node) == "request":
                taint.add(self._source("user", f"request.{node.attr}", node))
            return taint
        if isinstance(node, ast.Subscript):
            taint = self._expression(node.value, environment) | self._expression(
                node.slice, environment
            )
            if self._root_name(node.value) == "request":
                taint.add(self._source("user", "request data", node))
            return taint
        if isinstance(node, ast.Call):
            name = call_name(node) or ""
            argument_taints = [self._expression(argument, environment) for argument in node.args]
            keyword_taints = [
                self._expression(keyword.value, environment) for keyword in node.keywords
            ]
            self._check_call_sink(node, name, argument_taints, environment)
            source = self._call_source(name, node)
            combined = self._combine(*argument_taints, *keyword_taints)
            if source:
                combined.add(source)
            return combined
        combined: Taint = set()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                combined.update(self._expression(child, environment))
        return combined

    def _check_call_sink(
        self, node: ast.Call, name: str, argument_taints: Sequence[Taint], environment: Environment
    ) -> None:
        first = argument_taints[0] if argument_taints else set()
        if name in {"eval", "exec"} and first:
            self._report(CODE_SINK, node, name, first)
        elif name == "os.system" and first:
            self._report(SHELL_SINK, node, name, first)
        elif name in SUBPROCESS_CALLS and first:
            self._report(SHELL_SINK, node, name, first)
        elif (name.endswith(".execute") or name.endswith(".executemany")) and first:
            self._report(SQL_SINK, node, name, first)
        elif name.startswith(HTTP_CLIENT_PREFIXES) and any(
            name.endswith(suffix) for suffix in HTTP_CALL_SUFFIXES
        ) and first:
            self._report(URL_SINK, node, name, first)

        dispatch_taint: Taint = set()
        if isinstance(node.func, ast.Subscript):
            dispatch_taint = self._expression(node.func.slice, environment)
        elif isinstance(node.func, ast.Call) and call_name(node.func) == "getattr":
            if len(node.func.args) >= 2:
                dispatch_taint = self._expression(node.func.args[1], environment)
        if dispatch_taint:
            self._report(TOOL_SINK, node, "dynamic dispatch", dispatch_taint)

    def _report(self, sink: Sink, node: ast.Call, name: str, taint: Taint) -> None:
        location = (sink.rule_id, node.lineno, node.col_offset + 1)
        if location in self._seen:
            return
        self._seen.add(location)
        ordered = sorted(taint, key=lambda source: (source.line, source.column, source.label))
        source_kinds = sorted({source.kind for source in ordered})
        evidence = tuple(
            Evidence(source.line, source.column, f"{source.kind} source: {source.label}")
            for source in ordered[:4]
        ) + (Evidence(node.lineno, node.col_offset + 1, f"reaches {name}"),)
        self.findings.append(
            Finding(
                rule_id=sink.rule_id,
                title=sink.title,
                severity=sink.severity,
                path=self.path,
                line=node.lineno,
                column=node.col_offset + 1,
                message=sink.message.format(sink=name) + f" Source: {', '.join(source_kinds)}.",
                remediation=sink.remediation,
                evidence=evidence,
            )
        )

    def _call_source(self, name: str, node: ast.Call) -> Optional[TaintSource]:
        lowered = name.lower()
        if lowered in USER_CALLS or lowered.startswith("request."):
            return self._source("user", name or "request", node)
        if any(marker in lowered for marker in MODEL_CALL_MARKERS):
            return self._source("model", name, node)
        return None

    def _named_source(self, name: str, node: ast.AST) -> Optional[TaintSource]:
        if MODEL_PARAMETER.search(name):
            return self._source("model", name, node)
        if USER_PARAMETER.search(name):
            return self._source("user", name, node)
        return None

    @staticmethod
    def _source(kind: str, label: str, node: ast.AST) -> TaintSource:
        return TaintSource(
            kind,
            label,
            getattr(node, "lineno", 1),
            getattr(node, "col_offset", 0) + 1,
        )

    def _assign(self, target: ast.AST, taint: Taint, environment: Environment) -> None:
        if isinstance(target, ast.Name):
            if taint:
                environment[target.id] = set(taint)
            else:
                environment.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._assign(element, taint, environment)

    @staticmethod
    def _root_name(node: ast.AST) -> Optional[str]:
        current = node
        while isinstance(current, (ast.Attribute, ast.Subscript)):
            current = current.value
        return current.id if isinstance(current, ast.Name) else None

    @staticmethod
    def _combine(*taints: Taint) -> Taint:
        combined: Taint = set()
        for taint in taints:
            combined.update(taint)
        return combined

    @staticmethod
    def _copy_environment(environment: Environment) -> Environment:
        return {name: set(taint) for name, taint in environment.items()}

    @classmethod
    def _merge_environments(cls, *environments: Environment) -> Environment:
        merged: Environment = {}
        for environment in environments:
            for name, taint in environment.items():
                merged.setdefault(name, set()).update(taint)
        return merged
