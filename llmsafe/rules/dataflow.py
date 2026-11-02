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

MCP_SERVER_CONSTRUCTORS = {
    "mcp.server.MCPServer",
    "mcp.server.mcpserver.MCPServer",
    "mcp.server.fastmcp.FastMCP",
}
MCP_CONTEXT_ANNOTATIONS = {
    "mcp.server.Context",
    "mcp.server.mcpserver.Context",
    "mcp.server.mcpserver.context.Context",
    "mcp.server.fastmcp.Context",
    "mcp.server.fastmcp.server.Context",
}
MCP_RESOLVE_ANNOTATIONS = {
    "mcp.server.mcpserver.Resolve",
    "mcp.server.mcpserver.resolve.Resolve",
}
OPENAI_TOOL_DECORATORS = {
    "agents.function_tool",
    "agents.tool.function_tool",
    "agents.decorators.function_tool",
    "agents.decorators.tool",
}
OPENAI_TOOL_CONTEXT_ANNOTATIONS = {
    "agents.RunContextWrapper",
    "agents.run_context.RunContextWrapper",
    "agents.tool_context.ToolContext",
}
LANGCHAIN_TOOL_DECORATORS = {
    "langchain.tools.tool",
    "langchain_core.tools.tool",
    "langchain_core.tools.convert.tool",
}
LANGCHAIN_INJECTED_ANNOTATIONS = {
    "langchain.tools.ToolRuntime",
    "langchain_core.tools.ToolRuntime",
    "langchain_core.tools.base.ToolRuntime",
    "langchain.tools.InjectedToolArg",
    "langchain_core.tools.InjectedToolArg",
    "langgraph.prebuilt.InjectedState",
    "langgraph.prebuilt.InjectedStore",
}
PYDANTIC_AGENT_CONSTRUCTORS = {"pydantic_ai.Agent", "pydantic_ai.agent.Agent"}
PYDANTIC_CONTEXT_ANNOTATIONS = {
    "pydantic_ai.RunContext",
    "pydantic_ai.tools.RunContext",
}


@dataclass(frozen=True)
class TaintSource:
    """Origin of data that crosses an application trust boundary."""

    kind: str
    label: str
    line: int
    column: int
    path: Optional[Path] = None


Taint = Set[TaintSource]
Environment = Dict[str, Taint]

# Internal environment keys cannot collide with Python identifiers. They keep
# container identities and field taints inside the existing branch-merge model.
_REFERENCE_PREFIX = "\0ref:"
_CLASS_PREFIX = "\0class:"
_FIELD_PREFIX = "\0field:"
_UNKNOWN_FIELD = "*"


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
    returns: Tuple[TaintSource, ...]


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
# Narrow POSIX literal-only case: echo cannot reinterpret argument data as
# source code, even if the argument itself came from an untrusted user.
# Other programs may accept dangerous flags, so no generic shell=False bypass.
DATA_ONLY_EXECUTABLES = {"/bin/echo", "/usr/bin/echo"}
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
            separator = "" if not module or module.endswith(".") else "."
            imported_name = f"{module}{separator}{alias.name}"
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

    def visit_MatchAs(self, node: ast.AST) -> None:  # noqa: N802
        name = getattr(node, "name", None)
        pattern = getattr(node, "pattern", None)
        if name:
            self.bindings.add(name)
        if pattern:
            self.visit(pattern)

    def visit_MatchStar(self, node: ast.AST) -> None:  # noqa: N802
        name = getattr(node, "name", None)
        if name:
            self.bindings.add(name)

    def visit_MatchMapping(self, node: ast.AST) -> None:  # noqa: N802
        rest = getattr(node, "rest", None)
        if rest:
            self.bindings.add(rest)
        self.generic_visit(node)


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
        module_imports, module_shadowed = self._scope_import_context(tree.body)
        mcp_tool_functions = self._mcp_tool_functions(
            tree.body,
            module_imports,
            module_shadowed,
        )
        openai_tool_functions = self._openai_tool_functions(
            tree.body,
            module_imports,
            module_shadowed,
        )
        langchain_tools, pydantic_tools = self._additional_tool_functions(
            tree.body, module_imports, module_shadowed
        )
        summaries = self._function_summaries(
            path,
            definitions,
            module_imports,
            module_shadowed,
        )
        summaries.update(self._class_method_summaries(
            path, tree.body, summaries, module_imports, module_shadowed
        ))
        harmless_maps = self._harmless_dispatch_maps(tree.body)
        analyzer = _ScopeAnalyzer(
            path,
            summaries,
            import_aliases=module_imports,
            shadowed_names=module_shadowed,
            harmless_dispatch_maps=harmless_maps,
        )
        analyzer.analyze_scope(tree.body, {})
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                environment = analyzer.parameter_environment(
                    node.args,
                    mcp_tool=id(node) in mcp_tool_functions,
                    openai_tool=id(node) in openai_tool_functions,
                    langchain_tool=id(node) in langchain_tools,
                    pydantic_tool=id(node) in pydantic_tools,
                )
                import_aliases, shadowed_names = self._function_import_context(
                    node,
                    module_imports,
                    module_shadowed,
                )
                collector = _ScopeBindingCollector()
                for stmt in node.body:
                    collector.visit(stmt)
                blocked = collector.bindings | {
                    arg.arg
                    for arg in (
                        *node.args.posonlyargs,
                        *node.args.args,
                        *node.args.kwonlyargs,
                    )
                }
                function_analyzer = _ScopeAnalyzer(
                    path,
                    summaries,
                    import_aliases=import_aliases,
                    shadowed_names=shadowed_names,
                    harmless_dispatch_maps=harmless_maps - blocked,
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

        summaries = {
            qualified_name: self._empty_function_summary(function)
            for qualified_name, (_, function) in function_nodes.items()
        }
        queue: Deque[str] = deque(sorted(function_nodes))
        queued = set(queue)
        while queue:
            qualified_name = queue.popleft()
            queued.discard(qualified_name)
            module, function = function_nodes[qualified_name]
            module_imports, module_shadowed = self._scope_import_context(module.tree.body)
            known = {
                call: summaries[target]
                for call, target in call_targets[qualified_name].items()
                if target in summaries
            }
            function_imports, function_shadowed = self._function_import_context(
                function,
                module_imports,
                module_shadowed,
            )
            updated = self._summarize_function(
                module.path,
                function,
                known,
                function_imports,
                function_shadowed,
            )
            if summaries.get(qualified_name) == updated:
                continue
            summaries[qualified_name] = updated
            for caller in sorted(dependents.get(qualified_name, set())):
                if caller not in queued:
                    queue.append(caller)
                    queued.add(caller)

        for module in sorted(modules.values(), key=lambda item: item.name):
            module_imports, module_shadowed = self._scope_import_context(module.tree.body)
            mcp_tool_functions = self._mcp_tool_functions(
                module.tree.body,
                module_imports,
                module_shadowed,
            )
            openai_tool_functions = self._openai_tool_functions(
                module.tree.body,
                module_imports,
                module_shadowed,
            )
            langchain_tools, pydantic_tools = self._additional_tool_functions(
                module.tree.body, module_imports, module_shadowed
            )
            known = self._project_summaries_for(
                module,
                module.tree,
                modules,
                function_names,
                summaries,
            )
            known.update(self._class_method_summaries(
                module.path, module.tree.body, known, module_imports, module_shadowed
            ))
            harmless_maps = self._harmless_dispatch_maps(module.tree.body)
            analyzer = _ScopeAnalyzer(
                module.path,
                known,
                import_aliases=module_imports,
                shadowed_names=module_shadowed,
                harmless_dispatch_maps=harmless_maps,
            )
            analyzer.analyze_scope(module.tree.body, {})
            for function in module.definitions.values():
                environment = analyzer.parameter_environment(
                    function.args,
                    mcp_tool=id(function) in mcp_tool_functions,
                    openai_tool=id(function) in openai_tool_functions,
                    langchain_tool=id(function) in langchain_tools,
                    pydantic_tool=id(function) in pydantic_tools,
                )
                import_aliases, shadowed_names = self._function_import_context(
                    function,
                    module_imports,
                    module_shadowed,
                )
                collector = _ScopeBindingCollector()
                for stmt in function.body:
                    collector.visit(stmt)
                blocked = collector.bindings | {
                    arg.arg
                    for arg in (
                        *function.args.posonlyargs,
                        *function.args.args,
                        *function.args.kwonlyargs,
                    )
                }
                function_analyzer = _ScopeAnalyzer(
                    module.path,
                    known,
                    import_aliases=import_aliases,
                    shadowed_names=shadowed_names,
                    harmless_dispatch_maps=harmless_maps - blocked,
                )
                function_analyzer.analyze_scope(function.body, environment)
                analyzer.findings.extend(function_analyzer.findings)
            yield from analyzer.findings

    def _class_method_summaries(
        self,
        path: Path,
        statements: Sequence[ast.stmt],
        known: Mapping[str, FunctionSummary],
        imports: Mapping[str, str],
        shadowed: Sequence[str],
    ) -> Dict[str, FunctionSummary]:
        """Summarize direct local methods without importing scanned classes."""
        methods: Dict[str, FunctionSummary] = {}
        # If local code replaces class methods, a statically summarized class
        # body cannot safely stand in for the runtime callable.
        mutated_classes: Set[str] = set()
        for statement in statements:
            if isinstance(statement, ast.ClassDef):
                continue
            for node in ast.walk(statement):
                if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    targets = (
                        node.targets if isinstance(node, ast.Assign) else (node.target,)
                    )
                    for target in targets:
                        if isinstance(target, ast.Attribute) and isinstance(
                            target.value, ast.Name
                        ):
                            mutated_classes.add(target.value.id)
                if isinstance(node, ast.Call) and call_name(node) in {
                    "setattr", "delattr"
                }:
                    if node.args and isinstance(node.args[0], ast.Name):
                        mutated_classes.add(node.args[0].id)
        for statement in statements:
            if not isinstance(statement, ast.ClassDef):
                continue
            if statement.name in mutated_classes or statement.bases:
                continue
            for method in statement.body:
                if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                # Only plain instance methods; classmethod/staticmethod/decorators
                # can alter the bound parameter layout at runtime.
                if method.decorator_list or not method.args.args:
                    continue
                first = method.args.args[0].arg
                summary = self._summarize_function(
                    path, method, known, imports, shadowed
                )
                if summary.positional_parameters[0] != first:
                    continue
                methods[f"{statement.name}.{method.name}"] = FunctionSummary(
                    tuple(p for p in summary.parameters if p != first),
                    summary.positional_parameters[1:],
                    summary.vararg,
                    summary.kwarg,
                    summary.sinks,
                    summary.returns,
                )
        return methods

    @staticmethod
    def _harmless_dispatch_maps(statements: Sequence[ast.stmt]) -> Set[str]:
        """Prove small immutable maps to side-effect-free constant functions."""
        safe_functions = {
            stmt.name
            for stmt in statements
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
            and not stmt.decorator_list
            and not (
                stmt.args.posonlyargs or stmt.args.args or stmt.args.kwonlyargs
                or stmt.args.vararg or stmt.args.kwarg
            )
            and len(stmt.body) == 1
            and isinstance(stmt.body[0], ast.Return)
            and isinstance(stmt.body[0].value, ast.Constant)
        }
        candidates: Set[str] = set()
        for stmt in statements:
            if not isinstance(stmt, ast.Assign) or len(stmt.targets) != 1:
                continue
            if not isinstance(stmt.targets[0], ast.Name) or not isinstance(stmt.value, ast.Dict):
                continue
            if not stmt.value.keys or not all(
                isinstance(key, ast.Constant) and isinstance(key.value, str)
                and isinstance(value, ast.Name) and value.id in safe_functions
                for key, value in zip(stmt.value.keys, stmt.value.values)
            ):
                continue
            candidates.add(stmt.targets[0].id)
        for name in tuple(candidates):
            bindings = 0
            unsafe = False
            for stmt in statements:
                for node in ast.walk(stmt):
                    if isinstance(node, ast.Name) and node.id == name:
                        if isinstance(node.ctx, (ast.Store, ast.Del)):
                            bindings += 1
                    if (
                        isinstance(node, ast.Subscript)
                        and isinstance(node.value, ast.Name)
                        and node.value.id == name
                        and isinstance(node.ctx, (ast.Store, ast.Del))
                    ):
                        unsafe = True
                    if isinstance(node, ast.Call) and any(
                        isinstance(arg, ast.Name) and arg.id == name
                        for arg in (*node.args, *(kw.value for kw in node.keywords))
                    ):
                        unsafe = True
                    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                        if node.value.id == name:
                            unsafe = True
                    if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name):
                        if node.value.id == name:
                            unsafe = True
            if unsafe or bindings != 1:
                candidates.discard(name)
        return candidates

    @classmethod
    def _scope_import_context(
        cls,
        statements: Sequence[ast.stmt],
        inherited_aliases: Optional[Mapping[str, str]] = None,
        inherited_shadowed: Sequence[str] = (),
        blocked: Sequence[str] = (),
    ) -> Tuple[Dict[str, str], Set[str]]:
        """Return resolvable imports and names whose API identity is shadowed."""

        collector = _ScopeBindingCollector()
        for statement in statements:
            collector.visit(statement)
        blocked_names = collector.bindings | set(blocked)
        local_imports = set(collector.imports)
        unresolved_imports = {
            name
            for name, targets in collector.imports.items()
            if len(targets) != 1 or next(iter(targets)).startswith(".")
        }
        shadowed_names = (
            (set(inherited_shadowed) - local_imports)
            | blocked_names
            | unresolved_imports
        )
        aliases = {
            name: target
            for name, target in (inherited_aliases or {}).items()
            if name not in shadowed_names and name not in local_imports
        }
        for name, targets in collector.imports.items():
            if name in shadowed_names or len(targets) != 1:
                continue
            target = next(iter(targets))
            if not target.startswith("."):
                aliases[name] = target
        return aliases, shadowed_names

    @classmethod
    def _function_import_context(
        cls,
        function: Union[ast.FunctionDef, ast.AsyncFunctionDef],
        inherited_aliases: Mapping[str, str],
        inherited_shadowed: Sequence[str],
    ) -> Tuple[Dict[str, str], Set[str]]:
        arguments = (
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
            *((function.args.vararg,) if function.args.vararg else ()),
            *((function.args.kwarg,) if function.args.kwarg else ()),
        )
        return cls._scope_import_context(
            function.body,
            inherited_aliases,
            inherited_shadowed,
            blocked=tuple(argument.arg for argument in arguments),
        )

    @classmethod
    def _mcp_tool_functions(
        cls,
        statements: Sequence[ast.stmt],
        import_aliases: Mapping[str, str],
        shadowed_names: Sequence[str],
    ) -> Set[int]:
        """Return official MCP SDK tool functions declared at module scope."""

        server_instances: Set[str] = set()
        tool_functions: Set[int] = set()
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if any(
                    cls._is_mcp_tool_decorator(decorator, server_instances)
                    for decorator in statement.decorator_list
                ):
                    tool_functions.add(id(statement))
                server_instances.discard(statement.name)
                continue
            if isinstance(statement, ast.ClassDef):
                server_instances.discard(statement.name)
                continue
            if isinstance(statement, ast.Import):
                server_instances.difference_update(
                    alias.asname or alias.name.split(".", 1)[0]
                    for alias in statement.names
                )
                continue
            if isinstance(statement, ast.ImportFrom):
                server_instances.difference_update(
                    alias.asname or alias.name
                    for alias in statement.names
                    if alias.name != "*"
                )
                continue

            value: Optional[ast.AST] = None
            targets: Sequence[ast.AST] = ()
            if isinstance(statement, ast.Assign):
                value = statement.value
                targets = statement.targets
            elif isinstance(statement, ast.AnnAssign):
                value = statement.value
                targets = (statement.target,)
            elif isinstance(statement, ast.AugAssign):
                targets = (statement.target,)

            assigned = cls._assigned_names(targets)
            server_instances.difference_update(assigned)
            if not isinstance(value, ast.Call):
                continue
            constructor = cls._resolved_external_name(
                call_name(value) or "",
                import_aliases,
                shadowed_names,
            )
            if constructor in MCP_SERVER_CONSTRUCTORS:
                server_instances.update(assigned)
        return tool_functions

    @classmethod
    def _openai_tool_functions(
        cls,
        statements: Sequence[ast.stmt],
        import_aliases: Mapping[str, str],
        shadowed_names: Sequence[str],
    ) -> Set[int]:
        """Return official OpenAI Agents SDK function tools declared at module scope."""

        return {
            id(statement)
            for statement in statements
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
            and any(
                cls._resolved_external_name(
                    cls._simple_expression_name(
                        decorator.func if isinstance(decorator, ast.Call) else decorator
                    )
                    or "",
                    import_aliases,
                    shadowed_names,
                )
                in OPENAI_TOOL_DECORATORS
                for decorator in statement.decorator_list
            )
        }

    @classmethod
    def _additional_tool_functions(
        cls,
        statements: Sequence[ast.stmt],
        import_aliases: Mapping[str, str],
        shadowed_names: Sequence[str],
    ) -> Tuple[Set[int], Set[int]]:
        """Identify explicit LangChain decorators and Pydantic Agent tools only.

        The Pydantic receiver must originate from a recognized constructor.
        Rebindings invalidate it; a similarly named object is not sufficient.
        """
        langchain: Set[int] = set()
        pydantic: Set[int] = set()
        agent_instances: Set[str] = set()
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in statement.decorator_list:
                    expression = decorator.func if isinstance(decorator, ast.Call) else decorator
                    name = cls._simple_expression_name(expression) or ""
                    if cls._resolved_external_name(
                        name, import_aliases, shadowed_names
                    ) in LANGCHAIN_TOOL_DECORATORS:
                        langchain.add(id(statement))
                    if (
                        isinstance(expression, ast.Attribute)
                        and expression.attr in {"tool", "tool_plain"}
                        and isinstance(expression.value, ast.Name)
                        and expression.value.id in agent_instances
                    ):
                        pydantic.add(id(statement))
                agent_instances.discard(statement.name)
                continue
            if isinstance(statement, ast.ClassDef):
                agent_instances.discard(statement.name)
                continue
            if isinstance(statement, (ast.Import, ast.ImportFrom)):
                continue
            value: Optional[ast.AST] = None
            targets: Sequence[ast.AST] = ()
            if isinstance(statement, ast.Assign):
                value = statement.value
                targets = statement.targets
            elif isinstance(statement, ast.AnnAssign):
                value = statement.value
                targets = (statement.target,)
            elif isinstance(statement, ast.AugAssign):
                targets = (statement.target,)
            assigned = cls._assigned_names(targets)
            was_agent = (
                isinstance(value, ast.Name) and value.id in agent_instances
            )
            agent_instances.difference_update(assigned)
            if was_agent:
                agent_instances.update(assigned)
            if isinstance(value, ast.Call):
                constructor = cls._resolved_external_name(
                    call_name(value) or "", import_aliases, shadowed_names
                )
                if constructor in PYDANTIC_AGENT_CONSTRUCTORS:
                    agent_instances.update(assigned)
        return langchain, pydantic

    @classmethod
    def _simple_expression_name(cls, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = cls._simple_expression_name(node.value)
            return f"{parent}.{node.attr}" if parent else None
        return None

    @staticmethod
    def _assigned_names(targets: Sequence[ast.AST]) -> Set[str]:
        names: Set[str] = set()
        pending = list(targets)
        while pending:
            target = pending.pop()
            if isinstance(target, ast.Name):
                names.add(target.id)
            elif isinstance(target, (ast.Tuple, ast.List)):
                pending.extend(target.elts)
        return names

    @staticmethod
    def _is_mcp_tool_decorator(decorator: ast.AST, server_instances: Set[str]) -> bool:
        expression = decorator.func if isinstance(decorator, ast.Call) else decorator
        return (
            isinstance(expression, ast.Attribute)
            and expression.attr == "tool"
            and isinstance(expression.value, ast.Name)
            and expression.value.id in server_instances
        )

    @staticmethod
    def _resolved_external_name(
        name: str,
        import_aliases: Mapping[str, str],
        shadowed_names: Sequence[str],
    ) -> str:
        first, separator, remainder = name.partition(".")
        if first in shadowed_names:
            return f"<shadowed>.{remainder}" if separator else "<shadowed>"
        resolved = import_aliases.get(first, first)
        return f"{resolved}.{remainder}" if separator else resolved

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
        module_shadowed: Sequence[str],
    ) -> Dict[str, FunctionSummary]:
        summaries = {
            name: self._empty_function_summary(function)
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

        queue: Deque[str] = deque(sorted(definitions))
        queued = set(queue)
        while queue:
            changed = queue.popleft()
            queued.discard(changed)
            function = definitions[changed]
            import_aliases, shadowed_names = self._function_import_context(
                function,
                module_imports,
                module_shadowed,
            )
            updated = self._summarize_function(
                path,
                function,
                summaries,
                import_aliases,
                shadowed_names,
            )
            if updated == summaries[changed]:
                continue
            summaries[changed] = updated
            for caller in sorted(dependents[changed]):
                if caller not in queued:
                    queue.append(caller)
                    queued.add(caller)
        return summaries

    @classmethod
    def _empty_function_summary(
        cls,
        function: Union[ast.FunctionDef, ast.AsyncFunctionDef],
    ) -> FunctionSummary:
        parameters, positional, vararg, kwarg = cls._function_parameters(function)
        return FunctionSummary(parameters, positional, vararg, kwarg, (), ())

    @staticmethod
    def _function_parameters(
        function: Union[ast.FunctionDef, ast.AsyncFunctionDef],
    ) -> Tuple[Tuple[str, ...], Tuple[str, ...], Optional[str], Optional[str]]:
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
        return tuple(parameters), positional, vararg, kwarg

    def _summarize_function(
        self,
        path: Path,
        function: Union[ast.FunctionDef, ast.AsyncFunctionDef],
        known_summaries: Mapping[str, FunctionSummary],
        import_aliases: Optional[Mapping[str, str]] = None,
        shadowed_names: Sequence[str] = (),
    ) -> FunctionSummary:
        parameters, positional, vararg, kwarg = self._function_parameters(function)
        environment = {
            argument.arg: {
                TaintSource(
                    "parameter",
                    argument.arg,
                    getattr(argument, "lineno", function.lineno),
                    getattr(argument, "col_offset", function.col_offset) + 1,
                    path,
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
            shadowed_names=shadowed_names,
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
        returns = tuple(
            sorted(
                analyzer.summary_returns,
                key=lambda source: (
                    source.kind,
                    source.label,
                    str(source.path or ""),
                    source.line,
                    source.column,
                ),
            )
        )
        return FunctionSummary(parameters, positional, vararg, kwarg, sinks, returns)


class _ScopeAnalyzer:
    def __init__(
        self,
        path: Path,
        function_summaries: Optional[Mapping[str, FunctionSummary]] = None,
        capture_parameter_sinks: bool = False,
        import_aliases: Optional[Mapping[str, str]] = None,
        shadowed_names: Sequence[str] = (),
        harmless_dispatch_maps: Sequence[str] = (),
    ) -> None:
        self.path = path
        self.function_summaries = dict(function_summaries or {})
        self.capture_parameter_sinks = capture_parameter_sinks
        self.import_aliases = dict(import_aliases or {})
        self.shadowed_names = set(shadowed_names)
        self.harmless_dispatch_maps = set(harmless_dispatch_maps)
        self.findings: List[Finding] = []
        self.summary_sinks: List[FunctionSink] = []
        self.summary_returns: Taint = set()
        self._seen: Set[Tuple[str, int, int, Tuple[str, ...]]] = set()

    def parameter_environment(
        self,
        arguments: ast.arguments,
        mcp_tool: bool = False,
        openai_tool: bool = False,
        langchain_tool: bool = False,
        pydantic_tool: bool = False,
    ) -> Environment:
        environment: Environment = {}
        all_arguments = (
            list(arguments.posonlyargs) + list(arguments.args) + list(arguments.kwonlyargs)
        )
        if arguments.vararg:
            all_arguments.append(arguments.vararg)
        if arguments.kwarg:
            all_arguments.append(arguments.kwarg)
        for argument in all_arguments:
            if mcp_tool:
                if self._mcp_injected_parameter(argument):
                    continue
                source = self._source(
                    "user",
                    f"MCP tool parameter: {argument.arg}",
                    argument,
                )
            elif openai_tool:
                if self._openai_tool_injected_parameter(argument):
                    continue
                source = self._source(
                    "model",
                    f"OpenAI function tool parameter: {argument.arg}",
                    argument,
                )
            elif langchain_tool or pydantic_tool:
                if self._framework_injected_parameter(
                    argument, langchain=langchain_tool
                ):
                    continue
                source = self._source(
                    "model",
                    f"{'LangChain' if langchain_tool else 'PydanticAI'} tool parameter: "
                    f"{argument.arg}",
                    argument,
                )
            else:
                source = self._named_source(argument.arg, argument)
            if source:
                environment[argument.arg] = {source}
        return environment

    def _mcp_injected_parameter(self, argument: ast.arg) -> bool:
        annotation = argument.annotation
        if annotation is None:
            return False
        annotation_base = annotation.value if isinstance(annotation, ast.Subscript) else annotation
        annotation_name = self._resolved_call_name(
            self._expression_name(annotation_base) or ""
        )
        if annotation_name in MCP_CONTEXT_ANNOTATIONS:
            return True
        return any(
            isinstance(node, ast.Call)
            and self._resolved_call_name(call_name(node) or "") in MCP_RESOLVE_ANNOTATIONS
            for node in ast.walk(annotation)
        )

    def _openai_tool_injected_parameter(self, argument: ast.arg) -> bool:
        annotation = argument.annotation
        if annotation is None:
            return False
        annotation_base = annotation.value if isinstance(annotation, ast.Subscript) else annotation
        annotation_name = self._resolved_call_name(
            self._expression_name(annotation_base) or ""
        )
        return annotation_name in OPENAI_TOOL_CONTEXT_ANNOTATIONS

    def _framework_injected_parameter(
        self, argument: ast.arg, langchain: bool
    ) -> bool:
        annotation = argument.annotation
        if annotation is None:
            return False
        base = annotation.value if isinstance(annotation, ast.Subscript) else annotation
        name = self._resolved_call_name(self._expression_name(base) or "")
        allowed = (
            LANGCHAIN_INJECTED_ANNOTATIONS
            if langchain
            else PYDANTIC_CONTEXT_ANNOTATIONS
        )
        return name in allowed

    @classmethod
    def _expression_name(cls, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = cls._expression_name(node.value)
            return f"{parent}.{node.attr}" if parent else None
        return None

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
                self._assign(target, taint, current, statement.value)
        elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
            self._assign(
                statement.target,
                self._expression(statement.value, current),
                current,
                statement.value,
            )
        elif isinstance(statement, ast.AugAssign):
            taint = self._expression(statement.value, current) | self._expression(
                statement.target, current
            )
            self._assign(statement.target, taint, current)
        elif isinstance(statement, ast.Expr):
            self._expression(statement.value, current)
        elif isinstance(statement, ast.Return):
            if statement.value is not None:
                taint = self._expression(statement.value, current)
                if self.capture_parameter_sinks:
                    self.summary_returns.update(taint)
        elif isinstance(statement, ast.Raise):
            if statement.exc is not None:
                self._expression(statement.exc, current)
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
            taint = set(environment.get(node.id, set()))
            for reference in self._references(node.id, environment):
                taint.update(self._all_fields(reference, environment))
            return taint
        if isinstance(node, ast.Constant):
            return set()
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            location = self._field_location(node)
            if location is not None:
                name, segments, indices = location
                references = self._references(name, environment)
                if references:
                    index_taint = self._combine(
                        *(self._expression(index, environment) for index in indices)
                    )
                    field_taint = self._combine(
                        *(self._read_path(reference, segments, environment)
                          for reference in references)
                    )
                    return field_taint | index_taint
            if isinstance(node, ast.Attribute):
                taint = self._expression(node.value, environment)
                if node.attr in USER_ATTRIBUTES and self._root_name(node) == "request":
                    taint.add(self._source("user", f"request.{node.attr}", node))
                return taint
            taint = self._expression(node.value, environment) | self._expression(
                node.slice, environment
            )
            if self._root_name(node.value) == "request":
                taint.add(self._source("user", "request data", node))
            return taint
        if isinstance(node, ast.Call):
            # A locally constructed dictionary's get() reads only the selected
            # field. Still include the default: it may be returned at runtime.
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and isinstance(node.func.value, ast.Name)
                and 1 <= len(node.args) <= 2
                and not node.keywords
            ):
                references = self._references(node.func.value.id, environment)
                if references and all(ref.kind == "heap-dict" for ref in references):
                    taint = self._expression(node.args[0], environment)
                    if len(node.args) == 2:
                        taint.update(self._expression(node.args[1], environment))
                    for reference in references:
                        taint.update(self._read_field(reference, node.args[0], environment))
                    return taint
            # setdefault mutates a missing key and returns its existing or new
            # value. Without a proven key-presence model, merge both possibilities.
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "setdefault"
                and isinstance(node.func.value, ast.Name)
                and 1 <= len(node.args) <= 2
                and not node.keywords
            ):
                references = self._references(node.func.value.id, environment)
                if references and all(ref.kind == "heap-dict" for ref in references):
                    key_taint = self._expression(node.args[0], environment)
                    default_taint = (
                        self._expression(node.args[1], environment)
                        if len(node.args) == 2
                        else set()
                    )
                    current_taint = self._combine(
                        *(self._read_field(reference, node.args[0], environment)
                          for reference in references)
                    )
                    combined = current_taint | default_taint | key_taint
                    token = self._field_token(node.args[0])
                    self._write_field(
                        references,
                        token if token is not None and not key_taint else _UNKNOWN_FIELD,
                        combined,
                        environment,
                    )
                    return combined
            name = call_name(node) or ""
            resolved_name = self._resolved_call_name(name)
            if name in {"setattr", "delattr"} and node.args:
                if isinstance(node.args[0], ast.Name):
                    self._invalidate_instance_class(node.args[0].id, environment)
            local_method = self._local_method_target(node, environment)
            receiver_taint = (
                self._expression(node.func.value, environment)
                if isinstance(node.func, ast.Attribute)
                else set()
            )
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
                known_local_method=local_method is not None,
            )
            self._check_function_sinks(
                node,
                local_method or name,
                argument_taints,
                keyword_taints,
                unpacked_keyword_taint,
            )
            # dict.update() mutates the object even though it returns None.
            # Evaluate all input expressions above, then apply writes so an
            # alias and the original variable observe the same field taint.
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "update"
                and isinstance(node.func.value, ast.Name)
            ):
                references = self._references(node.func.value.id, environment)
                if references and all(ref.kind == "heap-dict" for ref in references):
                    if len(node.args) == 1 and isinstance(node.args[0], ast.Dict):
                        fields = [
                            (
                                self._field_token(key) if key is not None else None,
                                self._expression(value, environment),
                            )
                            for key, value in zip(
                                node.args[0].keys, node.args[0].values
                            )
                        ]
                        for token, field_taint in fields:
                            self._write_field(
                                references,
                                token or _UNKNOWN_FIELD,
                                field_taint,
                                environment,
                            )
                    elif node.args:
                        self._write_field(
                            references,
                            _UNKNOWN_FIELD,
                            self._combine(*argument_taints),
                            environment,
                        )
                    for keyword, (_, field_taint) in zip(node.keywords, keyword_pairs):
                        token = (
                            f"str:{keyword.arg!r}"
                            if keyword.arg is not None
                            else _UNKNOWN_FIELD
                        )
                        self._write_field(
                            references, token, field_taint, environment
                        )
                    return set()
            summary = self.function_summaries.get(name)
            if summary is None:
                combined = self._combine(
                    receiver_taint,
                    *argument_taints,
                    *(taint for _, taint in keyword_pairs),
                )
            else:
                combined = self._summary_return_taint(
                    summary,
                    argument_taints,
                    keyword_taints,
                    unpacked_keyword_taint,
                )
            source = None if summary is not None else self._call_source(resolved_name, node)
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
        known_local_method: bool = False,
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
            # A fixed, known data-only executable invoked without a shell
            # does not parse untrusted argv[1:] as shell commands. This is
            # intentionally NOT a sanitizer for arbitrary programs/flags.
            safe_data_argv = self._literal_data_only_argv(node)
            if not safe_data_argv:
                # Explicit execution environment changes can control which
                # program runs, independent of whether args are constant.
                taint.update(
                    self._combine(
                        *(keyword_taints.get(key, set())
                          for key in ("executable", "shell"))
                    )
                )
            else:
                taint = set()
            if taint:
                self._report(SHELL_SINK, node, name, taint)
        elif (
            (name.endswith(".execute") or name.endswith(".executemany"))
            and not known_local_method
        ):
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
            closed_map = (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id in self.harmless_dispatch_maps
            )
            if not closed_map:
                dispatch_taint = self._expression(node.func.slice, environment)
        elif isinstance(node.func, ast.Call) and call_name(node.func) == "getattr":
            if len(node.func.args) >= 2:
                dispatch_taint = self._expression(node.func.args[1], environment)
        if dispatch_taint:
            self._report(TOOL_SINK, node, "dynamic dispatch", dispatch_taint)

    @staticmethod
    def _invalidate_instance_class(name: str, environment: Environment) -> None:
        """Conservatively poison class identity for all possible aliases."""
        current = environment.get(f"{_CLASS_PREFIX}{name}", set())
        if not current:
            return
        affected_labels = {source.label for source in current}
        for key, refs in tuple(environment.items()):
            if not key.startswith(_CLASS_PREFIX):
                continue
            if any(ref.label in affected_labels for ref in refs):
                environment[key] = {
                    TaintSource("class-unknown", source.label, 0, 0)
                    for source in refs
                }

    def _local_method_target(
        self, node: ast.Call, environment: Environment
    ) -> Optional[str]:
        func = node.func
        if not isinstance(func, ast.Attribute) or not isinstance(func.value, ast.Name):
            return None
        classes = environment.get(f"{_CLASS_PREFIX}{func.value.id}", set())
        if len(classes) != 1:
            return None
        selected = next(iter(classes))
        if selected.kind != "local-class":
            return None
        target = f"{selected.label}.{func.attr}"
        return target if target in self.function_summaries else None

    @staticmethod
    def _literal_data_only_argv(node: ast.Call) -> bool:
        """Prove a very narrow no-shell data-only subprocess call.

        Dynamic kwargs, changed execution environments, shell=True, relative
        executable names, and other programs all stay on the conservative path.
        """
        if any(keyword.arg is None for keyword in node.keywords):
            return False
        if any(
            keyword.arg in {"executable", "cwd", "env"} for keyword in node.keywords
        ):
            return False
        shell = next(
            (keyword.value for keyword in node.keywords if keyword.arg == "shell"),
            None,
        )
        if shell is not None and not (
            isinstance(shell, ast.Constant) and shell.value is False
        ):
            return False
        command = (
            node.args[0]
            if node.args
            else next(
                (keyword.value for keyword in node.keywords if keyword.arg == "args"),
                None,
            )
        )
        if not isinstance(command, (ast.List, ast.Tuple)) or not command.elts:
            return False
        if any(isinstance(item, ast.Starred) for item in command.elts):
            return False
        executable = command.elts[0]
        return (
            isinstance(executable, ast.Constant)
            and isinstance(executable.value, str)
            and executable.value in DATA_ONLY_EXECUTABLES
        )

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
            taint = self._bound_parameter_taint(
                summary,
                function_sink.parameters,
                argument_taints,
                keyword_taints,
                unpacked_keyword_taint,
            )
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

    @classmethod
    def _summary_return_taint(
        cls,
        summary: FunctionSummary,
        argument_taints: Sequence[Taint],
        keyword_taints: Mapping[str, Taint],
        unpacked_keyword_taint: Taint,
    ) -> Taint:
        parameters = tuple(
            source.label for source in summary.returns if source.kind == "parameter"
        )
        taint = cls._bound_parameter_taint(
            summary,
            parameters,
            argument_taints,
            keyword_taints,
            unpacked_keyword_taint,
        )
        taint.update(source for source in summary.returns if source.kind != "parameter")
        return taint

    @classmethod
    def _bound_parameter_taint(
        cls,
        summary: FunctionSummary,
        parameters: Sequence[str],
        argument_taints: Sequence[Taint],
        keyword_taints: Mapping[str, Taint],
        unpacked_keyword_taint: Taint,
    ) -> Taint:
        taint: Taint = set()
        for parameter in parameters:
            taint.update(keyword_taints.get(parameter, set()))
            if parameter in summary.positional_parameters:
                index = summary.positional_parameters.index(parameter)
                if index < len(argument_taints):
                    taint.update(argument_taints[index])
            elif parameter == summary.vararg:
                taint.update(
                    cls._combine(*argument_taints[len(summary.positional_parameters) :])
                )
            elif parameter == summary.kwarg:
                taint.update(unpacked_keyword_taint)
                extra = (
                    value
                    for key, value in keyword_taints.items()
                    if key not in summary.parameters
                )
                taint.update(cls._combine(*extra))
        return taint

    def _report(
        self,
        sink: Sink,
        node: ast.Call,
        name: str,
        taint: Taint,
        helper_evidence: Optional[Evidence] = None,
        summary_location: Optional[Tuple[Path, int, int]] = None,
    ) -> None:
        ordered = sorted(
            taint,
            key=lambda source: (
                str(source.path or ""),
                source.line,
                source.column,
                source.label,
            ),
        )
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
            Evidence(
                source.line,
                source.column,
                f"{source.kind} source: {source.label}",
                source.path if source.path is not None and source.path != self.path else None,
            )
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
        if first in self.shadowed_names:
            return f"<shadowed>.{remainder}" if separator else "<shadowed>"
        resolved = self.import_aliases.get(first, first)
        return f"{resolved}.{remainder}" if separator else resolved

    def _named_source(self, name: str, node: ast.AST) -> Optional[TaintSource]:
        if MODEL_PARAMETER.search(name):
            return self._source("model", name, node)
        if USER_PARAMETER.search(name):
            return self._source("user", name, node)
        return None

    def _source(self, kind: str, label: str, node: ast.AST) -> TaintSource:
        return TaintSource(
            kind,
            label,
            getattr(node, "lineno", 1),
            getattr(node, "col_offset", 0) + 1,
            self.path,
        )

    @staticmethod
    def _field_token(node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Constant) and type(node.value) in {str, int}:
            return f"{type(node.value).__name__}:{node.value!r}"
        return None

    @classmethod
    def _field_location(
        cls, node: ast.AST
    ) -> Optional[Tuple[str, Tuple[str, ...], Tuple[ast.AST, ...]]]:
        """Resolve at most three literal fields from a tracked local root."""
        segments: List[str] = []
        indices: List[ast.AST] = []
        current = node
        while isinstance(current, (ast.Subscript, ast.Attribute)) and len(segments) < 3:
            if isinstance(current, ast.Subscript):
                segments.append(cls._field_token(current.slice) or _UNKNOWN_FIELD)
                indices.append(current.slice)
            else:
                segments.append(f"attr:{current.attr}")
            current = current.value
        if not isinstance(current, ast.Name) or not segments:
            return None
        return current.id, tuple(reversed(segments)), tuple(indices)

    @staticmethod
    def _field_path(segments: Sequence[str]) -> str:
        return "\0".join(segments)

    @staticmethod
    def _references(name: str, environment: Environment) -> Taint:
        return set(environment.get(f"{_REFERENCE_PREFIX}{name}", set()))

    @staticmethod
    def _field_prefix(reference: TaintSource) -> str:
        if reference.kind == "heap-field":
            return reference.label
        return f"{_FIELD_PREFIX}{reference.label}:"

    @classmethod
    def _all_fields(cls, reference: TaintSource, environment: Environment) -> Taint:
        prefix = cls._field_prefix(reference)
        return cls._combine(
            *(taint for key, taint in environment.items() if key.startswith(prefix))
        )

    @classmethod
    def _read_field(
        cls, reference: TaintSource, index: ast.AST, environment: Environment
    ) -> Taint:
        token = cls._field_token(index) or _UNKNOWN_FIELD
        return cls._read_path(reference, (token,), environment)

    @classmethod
    def _read_path(
        cls,
        reference: TaintSource,
        segments: Sequence[str],
        environment: Environment,
    ) -> Taint:
        if _UNKNOWN_FIELD in segments:
            return cls._all_fields(reference, environment)
        prefix = cls._field_prefix(reference)
        taint: Taint = set()
        for depth in range(1, len(segments) + 1):
            parts = segments[:depth]
            exact = prefix + cls._field_path(parts)
            taint.update(environment.get(exact, set()))
            wildcard = prefix + cls._field_path((*parts[:-1], _UNKNOWN_FIELD))
            taint.update(environment.get(wildcard, set()))
            # An unknown ancestor key can designate any concrete container.
            # Preserve mutations to its descendants when a known path is read.
            taint.update(
                cls._combine(
                    *(value for key, value in environment.items()
                      if key.startswith(wildcard + "\0"))
                )
            )
            if depth == len(segments):
                taint.update(
                    cls._combine(
                        *(value for key, value in environment.items()
                          if key.startswith(exact + "\0"))
                    )
                )
        return taint

    @classmethod
    def _write_field(
        cls,
        references: Taint,
        token: str,
        field_taint: Taint,
        environment: Environment,
    ) -> None:
        for reference in references:
            field_key = cls._field_prefix(reference) + token
            if _UNKNOWN_FIELD in token.split("\0") or len(references) != 1:
                if field_taint:
                    environment.setdefault(field_key, set()).update(field_taint)
            else:
                # A definite assignment replaces previous nested children.
                for key in tuple(environment):
                    if key.startswith(field_key + "\0"):
                        del environment[key]
                if field_taint:
                    environment[field_key] = set(field_taint)
                else:
                    environment.pop(field_key, None)

    def _store_literal_fields(
        self,
        references: Taint,
        base: Tuple[str, ...],
        literal: ast.Dict,
        environment: Environment,
    ) -> None:
        for key, value in zip(literal.keys, literal.values):
            token = self._field_token(key) if key is not None else None
            path = (*base, token or _UNKNOWN_FIELD)
            joined = self._field_path(path)
            if isinstance(value, ast.Dict) and len(path) < 3:
                self._write_field(references, joined, set(), environment)
                self._store_literal_fields(references, path, value, environment)
            else:
                self._write_field(
                    references, joined, self._expression(value, environment),
                    environment
                )

    def _assign(
        self,
        target: ast.AST,
        taint: Taint,
        environment: Environment,
        value_node: Optional[ast.AST] = None,
    ) -> None:
        if isinstance(target, ast.Name):
            class_key = f"{_CLASS_PREFIX}{target.id}"
            if isinstance(value_node, ast.Call) and isinstance(value_node.func, ast.Name):
                class_name = value_node.func.id
                if any(name.startswith(class_name + ".") for name in self.function_summaries):
                    environment[class_key] = {TaintSource("local-class", class_name, 0, 0)}
                else:
                    environment.pop(class_key, None)
            elif isinstance(value_node, ast.Name):
                if f"{_CLASS_PREFIX}{value_node.id}" in environment:
                    environment[class_key] = set(environment[f"{_CLASS_PREFIX}{value_node.id}"])
                else:
                    environment.pop(class_key, None)
            else:
                environment.pop(class_key, None)
            reference_key = f"{_REFERENCE_PREFIX}{target.id}"
            if isinstance(value_node, ast.Dict):
                reference = TaintSource("heap-dict", str(id(value_node)), 0, 0)
                environment[reference_key] = {reference}
                environment.pop(target.id, None)
                self._store_literal_fields({reference}, (), value_node, environment)
            elif (
                isinstance(value_node, ast.Call)
                and self._resolved_call_name(call_name(value_node) or "")
                == "types.SimpleNamespace"
                and not value_node.args
                and all(keyword.arg is not None for keyword in value_node.keywords)
            ):
                reference = TaintSource("heap-object", str(id(value_node)), 0, 0)
                environment[reference_key] = {reference}
                environment.pop(target.id, None)
                for keyword in value_node.keywords:
                    self._write_field(
                        {reference}, f"attr:{keyword.arg}",
                        self._expression(keyword.value, environment), environment
                    )
            elif isinstance(value_node, ast.Name) and self._references(
                value_node.id, environment
            ):
                environment[reference_key] = self._references(value_node.id, environment)
                # Keep only the underlying scalar taint. Container fields remain
                # precise and are read from shared heap locations instead.
                scalar = set(environment.get(value_node.id, set()))
                if scalar:
                    environment[target.id] = scalar
                else:
                    environment.pop(target.id, None)
            elif isinstance(value_node, (ast.Subscript, ast.Attribute)):
                location = self._field_location(value_node)
                if location and _UNKNOWN_FIELD not in location[1]:
                    name, segments, _ = location
                    roots = self._references(name, environment)
                    if roots:
                        environment[reference_key] = {
                            TaintSource(
                                "heap-field",
                                self._field_prefix(ref) + self._field_path(segments) + "\0",
                                0, 0
                            )
                            for ref in roots
                        }
                        environment.pop(target.id, None)
                    else:
                        environment.pop(reference_key, None)
                        if taint:
                            environment[target.id] = set(taint)
                        else:
                            environment.pop(target.id, None)
                else:
                    environment.pop(reference_key, None)
                    if taint:
                        environment[target.id] = set(taint)
                    else:
                        environment.pop(target.id, None)
            else:
                environment.pop(reference_key, None)
                if taint:
                    environment[target.id] = set(taint)
                else:
                    environment.pop(target.id, None)
        elif isinstance(target, (ast.Subscript, ast.Attribute)):
            if isinstance(target, ast.Attribute) and isinstance(
                target.value, ast.Name
            ):
                self._invalidate_instance_class(target.value.id, environment)
            if (
                isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Attribute)
                and target.value.attr == "__dict__"
                and isinstance(target.value.value, ast.Name)
            ):
                self._invalidate_instance_class(target.value.value.id, environment)
            location = self._field_location(target)
            if location:
                name, segments, indices = location
                references = self._references(name, environment)
                if references:
                    key_taint = self._combine(
                        *(self._expression(index, environment) for index in indices)
                    )
                    if key_taint:
                        segments = tuple(_UNKNOWN_FIELD for _ in segments)
                    token = self._field_path(segments)
                    field_taint = taint | key_taint
                    self._write_field(references, token, field_taint, environment)
                    if (
                        isinstance(value_node, ast.Dict)
                        and len(segments) < 3
                        and _UNKNOWN_FIELD not in segments
                    ):
                        self._store_literal_fields(references, segments, value_node, environment)
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
