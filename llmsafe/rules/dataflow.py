"""Local and inter-procedural dataflow analysis for agent trust boundaries."""

import ast
import os
import re
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Deque, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple, Union

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
MODEL_CALL_NAMES = {
    "runner.run",
    "runner.run_streamed",
    "runner.run_sync",
}
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


@dataclass(frozen=True)
class FunctionSink:
    """A local function parameter reaching a sensitive operation."""

    sink: Sink
    sink_name: str
    path: Path
    line: int
    column: int
    parameters: Tuple[str, ...]


@dataclass(frozen=True)
class FunctionSummary:
    """Security-relevant dataflow summary for one local function."""

    parameters: Tuple[str, ...]
    positional_parameters: Tuple[str, ...]
    vararg: Optional[str]
    kwarg: Optional[str]
    sinks: Tuple[FunctionSink, ...]


@dataclass(frozen=True)
class ImportedSymbol:
    """One statically resolvable ``from module import symbol`` binding."""

    module: str
    symbol: str


@dataclass(frozen=True)
class ModuleInfo:
    """Parsed local module and the import bindings visible at module scope."""

    name: str
    path: Path
    tree: ast.Module
    definitions: Mapping[str, Union[ast.FunctionDef, ast.AsyncFunctionDef]]
    symbol_imports: Mapping[str, ImportedSymbol]
    module_imports: Mapping[str, str]


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
    ".stream",
}
HTTP_CLIENT_PREFIXES = ("httpx.", "requests.", "urllib3.")
HTTP_METHOD_URL_SUFFIXES = (".request", ".stream")


class _ScopeBindingCollector(ast.NodeVisitor):
    """Collect import candidates and names rebound in one lexical scope."""

    def __init__(self) -> None:
        self.bindings: Set[str] = set()
        self.imports: Dict[str, Set[str]] = {}

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            local_name = alias.asname or alias.name.split(".", 1)[0]
            imported_name = alias.name if alias.asname else local_name
            self.imports.setdefault(local_name, set()).add(imported_name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        module = "." * node.level + (node.module or "")
        for alias in node.names:
            if alias.name == "*":
                continue
            local_name = alias.asname or alias.name
            imported_name = f"{module}.{alias.name}".strip(".")
            self.imports.setdefault(local_name, set()).add(imported_name)

    def visit_Name(self, node: ast.Name) -> None:  # noqa: N802
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.bindings.add(node.id)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self.bindings.add(node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self.bindings.add(node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        self.bindings.add(node.name)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:  # noqa: N802
        if node.name:
            self.bindings.add(node.name)
        for statement in node.body:
            self.visit(statement)


class DataflowRule:
    """Trace trust-boundary data to security-sensitive operations."""

    def scan(self, path: Path, content: str) -> Iterable[Finding]:
        if path.suffix.lower() != ".py":
            return
        tree = parse_python(content)
        if not isinstance(tree, ast.Module):
            return

        definitions = {
            node.name: node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        module_imports = self._scope_import_aliases(tree.body)
        summaries = self._function_summaries(path, definitions, module_imports)
        analyzer = _ScopeAnalyzer(path, summaries, import_aliases=module_imports)
        analyzer.analyze_scope(tree.body, {})
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                environment = analyzer.parameter_environment(node.args)
                import_aliases = self._function_import_aliases(node, module_imports)
                function_analyzer = _ScopeAnalyzer(
                    path,
                    summaries,
                    import_aliases=import_aliases,
                )
                function_analyzer.analyze_scope(node.body, environment)
                analyzer.findings.extend(function_analyzer.findings)
        yield from analyzer.findings

    def scan_project(self, files: Mapping[Path, str]) -> Iterable[Finding]:
        """Analyze included Python modules as one bounded local import graph."""

        modules = self._project_modules(files)
        if not modules:
            return
        function_nodes = {
            f"{module.name}.{name}": (module, function)
            for module in modules.values()
            for name, function in module.definitions.items()
        }
        function_names = set(function_nodes)
        call_targets = {
            qualified_name: self._project_call_targets(
                module,
                function,
                modules,
                function_names,
            )
            for qualified_name, (module, function) in function_nodes.items()
        }
        dependents: Dict[str, Set[str]] = {name: set() for name in function_nodes}
        for caller, targets in call_targets.items():
            for callee in set(targets.values()):
                dependents.setdefault(callee, set()).add(caller)

        summaries: Dict[str, FunctionSummary] = {}
        queue: Deque[str] = deque(sorted(function_nodes))
        queued = set(queue)
        while queue:
            qualified_name = queue.popleft()
            queued.discard(qualified_name)
            module, function = function_nodes[qualified_name]
            module_imports = self._scope_import_aliases(module.tree.body)
            known = {
                call: summaries[target]
                for call, target in call_targets[qualified_name].items()
                if target in summaries
            }
            updated = self._summarize_function(
                module.path,
                function,
                known,
                self._function_import_aliases(function, module_imports),
            )
            if summaries.get(qualified_name) == updated:
                continue
            summaries[qualified_name] = updated
            for caller in sorted(dependents.get(qualified_name, set())):
                if caller not in queued:
                    queue.append(caller)
                    queued.add(caller)

        for module in sorted(modules.values(), key=lambda item: item.name):
            module_imports = self._scope_import_aliases(module.tree.body)
            known = self._project_summaries_for(
                module,
                module.tree,
                modules,
                function_names,
                summaries,
            )
            analyzer = _ScopeAnalyzer(module.path, known, import_aliases=module_imports)
            analyzer.analyze_scope(module.tree.body, {})
            for function in module.definitions.values():
                environment = analyzer.parameter_environment(function.args)
                import_aliases = self._function_import_aliases(function, module_imports)
                function_analyzer = _ScopeAnalyzer(
                    module.path,
                    known,
                    import_aliases=import_aliases,
                )
                function_analyzer.analyze_scope(function.body, environment)
                analyzer.findings.extend(function_analyzer.findings)
            yield from analyzer.findings

    @classmethod
    def _scope_import_aliases(
        cls,
        statements: Sequence[ast.stmt],
        inherited: Optional[Mapping[str, str]] = None,
        blocked: Sequence[str] = (),
    ) -> Dict[str, str]:
        """Return unambiguous import bindings that are not rebound in this scope."""

        collector = _ScopeBindingCollector()
        for statement in statements:
            collector.visit(statement)
        blocked_names = collector.bindings | set(blocked)
        local_imports = set(collector.imports)
        aliases = {
            name: target
            for name, target in (inherited or {}).items()
            if name not in blocked_names and name not in local_imports
        }
        for name, targets in collector.imports.items():
            if name not in blocked_names and len(targets) == 1:
                aliases[name] = next(iter(targets))
        return aliases

    @classmethod
    def _function_import_aliases(
        cls,
        function: Union[ast.FunctionDef, ast.AsyncFunctionDef],
        inherited: Mapping[str, str],
    ) -> Dict[str, str]:
        arguments = (
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
            *((function.args.vararg,) if function.args.vararg else ()),
            *((function.args.kwarg,) if function.args.kwarg else ()),
        )
        return cls._scope_import_aliases(
            function.body,
            inherited,
            blocked=tuple(argument.arg for argument in arguments),
        )

    @classmethod
    def _project_modules(cls, files: Mapping[Path, str]) -> Dict[str, ModuleInfo]:
        parsed: Dict[Path, Tuple[Path, ast.Module]] = {}
        for path, content in files.items():
            if path.suffix.lower() != ".py":
                continue
            tree = parse_python(content)
            if isinstance(tree, ast.Module):
                parsed[path] = (path.resolve(), tree)
        if not parsed:
            return {}

        common_root = Path(
            os.path.commonpath([str(absolute.parent) for absolute, _ in parsed.values()])
        )
        included_paths = {absolute for absolute, _ in parsed.values()}
        if (common_root / "__init__.py") in included_paths:
            common_root = common_root.parent

        basic: Dict[str, ModuleInfo] = {}
        ambiguous: Set[str] = set()
        for original, (absolute, tree) in parsed.items():
            try:
                relative = absolute.relative_to(common_root)
            except ValueError:
                continue
            parts = list(relative.parts)
            if relative.name == "__init__.py":
                parts = parts[:-1]
            else:
                parts[-1] = relative.stem
            if not parts:
                continue
            module_name = ".".join(parts)
            if module_name in basic:
                ambiguous.add(module_name)
                continue
            definitions = {
                node.name: node
                for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            basic[module_name] = ModuleInfo(
                module_name,
                original,
                tree,
                definitions,
                {},
                {},
            )
        for module_name in ambiguous:
            basic.pop(module_name, None)

        module_names = set(basic)
        modules: Dict[str, ModuleInfo] = {}
        for module_name, info in basic.items():
            symbol_imports, module_imports = cls._module_imports(info, module_names)
            modules[module_name] = ModuleInfo(
                info.name,
                info.path,
                info.tree,
                info.definitions,
                symbol_imports,
                module_imports,
            )
        return modules

    @classmethod
    def _module_imports(
        cls,
        module: ModuleInfo,
        module_names: Set[str],
    ) -> Tuple[Dict[str, ImportedSymbol], Dict[str, str]]:
        symbol_imports: Dict[str, ImportedSymbol] = {}
        module_imports: Dict[str, str] = {}
        for node in module.tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local_name = alias.asname or alias.name.split(".", 1)[0]
                    imported_module = alias.name if alias.asname else local_name
                    module_imports[local_name] = imported_module
            elif isinstance(node, ast.ImportFrom):
                imported_module = cls._absolute_import_name(module, node)
                if not imported_module:
                    continue
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    local_name = alias.asname or alias.name
                    possible_module = f"{imported_module}.{alias.name}"
                    if possible_module in module_names:
                        module_imports[local_name] = possible_module
                    else:
                        symbol_imports[local_name] = ImportedSymbol(
                            imported_module,
                            alias.name,
                        )
        return symbol_imports, module_imports

    @staticmethod
    def _absolute_import_name(module: ModuleInfo, node: ast.ImportFrom) -> str:
        if node.level == 0:
            return node.module or ""
        package = (
            module.name
            if module.path.name == "__init__.py"
            else module.name.rpartition(".")[0]
        )
        parts = package.split(".") if package else []
        parents = node.level - 1
        if parents > len(parts):
            return ""
        if parents:
            parts = parts[:-parents]
        if node.module:
            parts.extend(node.module.split("."))
        return ".".join(parts)

    @classmethod
    def _project_summaries_for(
        cls,
        module: ModuleInfo,
        node: ast.AST,
        modules: Mapping[str, ModuleInfo],
        function_names: Set[str],
        summaries: Mapping[str, FunctionSummary],
    ) -> Dict[str, FunctionSummary]:
        targets = cls._project_call_targets(module, node, modules, function_names)
        return {
            call: summaries[target]
            for call, target in targets.items()
            if target in summaries
        }

    @classmethod
    def _project_call_targets(
        cls,
        module: ModuleInfo,
        node: ast.AST,
        modules: Mapping[str, ModuleInfo],
        function_names: Set[str],
    ) -> Dict[str, str]:
        targets: Dict[str, str] = {}
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            name = call_name(child)
            if not name:
                continue
            target = cls._resolve_project_function(
                module.name,
                name,
                modules,
                function_names,
                set(),
            )
            if target is not None:
                targets[name] = target
        return targets

    @classmethod
    def _resolve_project_function(
        cls,
        module_name: str,
        symbol: str,
        modules: Mapping[str, ModuleInfo],
        function_names: Set[str],
        seen: Set[Tuple[str, str]],
    ) -> Optional[str]:
        state = (module_name, symbol)
        if state in seen or not symbol:
            return None
        seen.add(state)
        direct = f"{module_name}.{symbol}"
        if direct in function_names:
            return direct
        module = modules.get(module_name)
        if module is None:
            return None

        first, separator, remainder = symbol.partition(".")
        imported_symbol = module.symbol_imports.get(first)
        if imported_symbol is not None:
            target_symbol = imported_symbol.symbol
            if separator:
                target_symbol = f"{target_symbol}.{remainder}"
            return cls._resolve_project_function(
                imported_symbol.module,
                target_symbol,
                modules,
                function_names,
                seen,
            )
        imported_module = module.module_imports.get(first)
        if imported_module is not None and separator:
            return cls._resolve_project_function(
                imported_module,
                remainder,
                modules,
                function_names,
                seen,
            )
        child_module = f"{module_name}.{first}"
        if separator and child_module in modules:
            return cls._resolve_project_function(
                child_module,
                remainder,
                modules,
                function_names,
                seen,
            )
        return None

    def _function_summaries(
        self,
        path: Path,
        definitions: Mapping[str, Union[ast.FunctionDef, ast.AsyncFunctionDef]],
        module_imports: Mapping[str, str],
    ) -> Dict[str, FunctionSummary]:
        summaries = {
            name: self._summarize_function(
                path,
                function,
                {},
                self._function_import_aliases(function, module_imports),
            )
            for name, function in definitions.items()
        }
        dependents: Dict[str, Set[str]] = {name: set() for name in definitions}
        for caller, function in definitions.items():
            for node in ast.walk(function):
                if not isinstance(node, ast.Call):
                    continue
                callee = call_name(node)
                if callee in definitions:
                    dependents[callee].add(caller)

        queue: Deque[str] = deque(name for name, summary in summaries.items() if summary.sinks)
        queued = set(queue)
        while queue:
            changed = queue.popleft()
            queued.discard(changed)
            for caller in sorted(dependents[changed]):
                function = definitions[caller]
                updated = self._summarize_function(
                    path,
                    function,
                    summaries,
                    self._function_import_aliases(function, module_imports),
                )
                if updated == summaries[caller]:
                    continue
                summaries[caller] = updated
                if caller not in queued:
                    queue.append(caller)
                    queued.add(caller)
        return summaries

    def _summarize_function(
        self,
        path: Path,
        function: Union[ast.FunctionDef, ast.AsyncFunctionDef],
        known_summaries: Mapping[str, FunctionSummary],
        import_aliases: Optional[Mapping[str, str]] = None,
    ) -> FunctionSummary:
        positional = tuple(
            argument.arg for argument in (*function.args.posonlyargs, *function.args.args)
        )
        keyword_only = tuple(argument.arg for argument in function.args.kwonlyargs)
        vararg = function.args.vararg.arg if function.args.vararg else None
        kwarg = function.args.kwarg.arg if function.args.kwarg else None
        parameters = (*positional, *keyword_only)
        if vararg:
            parameters = (*parameters, vararg)
        if kwarg:
            parameters = (*parameters, kwarg)
        environment = {
            argument.arg: {
                TaintSource(
                    "parameter",
                    argument.arg,
                    getattr(argument, "lineno", function.lineno),
                    getattr(argument, "col_offset", function.col_offset) + 1,
                )
            }
            for argument in (
                *function.args.posonlyargs,
                *function.args.args,
                *function.args.kwonlyargs,
                *((function.args.vararg,) if function.args.vararg else ()),
                *((function.args.kwarg,) if function.args.kwarg else ()),
            )
        }
        analyzer = _ScopeAnalyzer(
            path,
            known_summaries,
            capture_parameter_sinks=True,
            import_aliases=import_aliases,
        )
        analyzer.analyze_scope(function.body, environment)
        unique = {
            (
                item.sink.rule_id,
                item.sink_name,
                item.path,
                item.line,
                item.column,
                item.parameters,
            ): item
            for item in analyzer.summary_sinks
        }
        sinks = tuple(unique[key] for key in sorted(unique))
        return FunctionSummary(tuple(parameters), positional, vararg, kwarg, sinks)


class _ScopeAnalyzer:
    def __init__(
        self,
        path: Path,
        function_summaries: Optional[Mapping[str, FunctionSummary]] = None,
        capture_parameter_sinks: bool = False,
        import_aliases: Optional[Mapping[str, str]] = None,
    ) -> None:
        self.path = path
        self.function_summaries = dict(function_summaries or {})
        self.capture_parameter_sinks = capture_parameter_sinks
        self.import_aliases = dict(import_aliases or {})
        self.findings: List[Finding] = []
        self.summary_sinks: List[FunctionSink] = []
        self._seen: Set[Tuple[str, int, int, Tuple[str, ...]]] = set()

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
            resolved_name = self._resolved_call_name(name)
            argument_taints = [self._expression(argument, environment) for argument in node.args]
            keyword_pairs = [
                (keyword.arg, self._expression(keyword.value, environment))
                for keyword in node.keywords
            ]
            keyword_taints = {name: taint for name, taint in keyword_pairs if name is not None}
            unpacked_keyword_taint = self._combine(
                *(taint for name, taint in keyword_pairs if name is None)
            )
            self._check_call_sink(
                node,
                resolved_name,
                argument_taints,
                keyword_taints,
                unpacked_keyword_taint,
                environment,
            )
            self._check_function_sinks(
                node,
                name,
                argument_taints,
                keyword_taints,
                unpacked_keyword_taint,
            )
            source = self._call_source(resolved_name, node)
            combined = self._combine(
                *argument_taints, *(taint for _, taint in keyword_pairs)
            )
            if source:
                combined.add(source)
            return combined
        combined: Taint = set()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                combined.update(self._expression(child, environment))
        return combined

    def _check_call_sink(
        self,
        node: ast.Call,
        name: str,
        argument_taints: Sequence[Taint],
        keyword_taints: Mapping[str, Taint],
        unpacked_keyword_taint: Taint,
        environment: Environment,
    ) -> None:
        if name in {"eval", "exec"}:
            taint = self._sink_argument_taint(
                argument_taints,
                keyword_taints,
                unpacked_keyword_taint,
                keyword_names=("source",),
            )
            if taint:
                self._report(CODE_SINK, node, name, taint)
        elif name == "os.system":
            taint = self._sink_argument_taint(
                argument_taints,
                keyword_taints,
                unpacked_keyword_taint,
                keyword_names=("command",),
            )
            if taint:
                self._report(SHELL_SINK, node, name, taint)
        elif name in SUBPROCESS_CALLS:
            taint = self._sink_argument_taint(
                argument_taints,
                keyword_taints,
                unpacked_keyword_taint,
                keyword_names=("args",),
            )
            if taint:
                self._report(SHELL_SINK, node, name, taint)
        elif name.endswith(".execute") or name.endswith(".executemany"):
            taint = self._sink_argument_taint(
                argument_taints,
                keyword_taints,
                unpacked_keyword_taint,
                keyword_names=("operation", "query", "sql", "statement"),
            )
            if taint:
                self._report(SQL_SINK, node, name, taint)
        elif name.startswith(HTTP_CLIENT_PREFIXES) and any(
            name.endswith(suffix) for suffix in HTTP_CALL_SUFFIXES
        ):
            positional_index = 1 if name.endswith(HTTP_METHOD_URL_SUFFIXES) else 0
            taint = self._sink_argument_taint(
                argument_taints,
                keyword_taints,
                unpacked_keyword_taint,
                positional_index=positional_index,
                keyword_names=("url",),
            )
            if taint:
                self._report(URL_SINK, node, name, taint)

        dispatch_taint: Taint = set()
        if isinstance(node.func, ast.Subscript):
            dispatch_taint = self._expression(node.func.slice, environment)
        elif isinstance(node.func, ast.Call) and call_name(node.func) == "getattr":
            if len(node.func.args) >= 2:
                dispatch_taint = self._expression(node.func.args[1], environment)
        if dispatch_taint:
            self._report(TOOL_SINK, node, "dynamic dispatch", dispatch_taint)

    @classmethod
    def _sink_argument_taint(
        cls,
        argument_taints: Sequence[Taint],
        keyword_taints: Mapping[str, Taint],
        unpacked_keyword_taint: Taint,
        positional_index: int = 0,
        keyword_names: Sequence[str] = (),
    ) -> Taint:
        """Return taint that can bind to one security-sensitive call parameter."""

        explicitly_bound = positional_index < len(argument_taints) or any(
            name in keyword_taints for name in keyword_names
        )
        taint = set() if explicitly_bound else set(unpacked_keyword_taint)
        if positional_index < len(argument_taints):
            taint.update(argument_taints[positional_index])
        taint.update(
            cls._combine(*(keyword_taints.get(name, set()) for name in keyword_names))
        )
        return taint

    def _check_function_sinks(
        self,
        node: ast.Call,
        name: str,
        argument_taints: Sequence[Taint],
        keyword_taints: Mapping[str, Taint],
        unpacked_keyword_taint: Taint,
    ) -> None:
        summary = self.function_summaries.get(name)
        if summary is None:
            return
        for function_sink in summary.sinks:
            taint: Taint = set()
            for parameter in function_sink.parameters:
                taint.update(keyword_taints.get(parameter, set()))
                if parameter in summary.positional_parameters:
                    index = summary.positional_parameters.index(parameter)
                    if index < len(argument_taints):
                        taint.update(argument_taints[index])
                elif parameter == summary.vararg:
                    taint.update(
                        self._combine(*argument_taints[len(summary.positional_parameters) :])
                    )
                elif parameter == summary.kwarg:
                    taint.update(unpacked_keyword_taint)
                    extra = (
                        value
                        for key, value in keyword_taints.items()
                        if key not in summary.parameters
                    )
                    taint.update(self._combine(*extra))
            if not taint:
                continue
            display_name = (
                function_sink.sink_name
                if self.capture_parameter_sinks
                else f"{name}() -> {function_sink.sink_name}"
            )
            helper_evidence = None
            if not self.capture_parameter_sinks:
                helper_evidence = Evidence(
                    function_sink.line,
                    function_sink.column,
                    f"local helper reaches {function_sink.sink_name}",
                    function_sink.path if function_sink.path != self.path else None,
                )
            self._report(
                function_sink.sink,
                node,
                display_name,
                taint,
                helper_evidence=helper_evidence,
                summary_location=(
                    function_sink.path,
                    function_sink.line,
                    function_sink.column,
                ),
            )

    def _report(
        self,
        sink: Sink,
        node: ast.Call,
        name: str,
        taint: Taint,
        helper_evidence: Optional[Evidence] = None,
        summary_location: Optional[Tuple[Path, int, int]] = None,
    ) -> None:
        ordered = sorted(taint, key=lambda source: (source.line, source.column, source.label))
        parameters = tuple(
            sorted({source.label for source in ordered if source.kind == "parameter"})
        )
        location = (
            sink.rule_id,
            node.lineno,
            node.col_offset + 1,
            parameters if self.capture_parameter_sinks else (),
        )
        if location in self._seen:
            return
        self._seen.add(location)
        if self.capture_parameter_sinks:
            if parameters:
                summary_path, summary_line, summary_column = summary_location or (
                    self.path,
                    node.lineno,
                    node.col_offset + 1,
                )
                self.summary_sinks.append(
                    FunctionSink(
                        sink,
                        name,
                        summary_path,
                        summary_line,
                        summary_column,
                        parameters,
                    )
                )
            return
        source_kinds = sorted({source.kind for source in ordered})
        evidence = tuple(
            Evidence(source.line, source.column, f"{source.kind} source: {source.label}")
            for source in ordered[:4]
        )
        if helper_evidence:
            evidence += (helper_evidence,)
        evidence += (Evidence(node.lineno, node.col_offset + 1, f"reaches {name}"),)
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
        model_call = lowered in MODEL_CALL_NAMES or any(
            lowered.endswith(f".{call}") for call in MODEL_CALL_NAMES
        )
        if model_call or any(marker in lowered for marker in MODEL_CALL_MARKERS):
            return self._source("model", name, node)
        return None

    def _resolved_call_name(self, name: str) -> str:
        first, separator, remainder = name.partition(".")
        resolved = self.import_aliases.get(first, first)
        return f"{resolved}.{remainder}" if separator else resolved

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
