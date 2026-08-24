# Architecture

LLMSafe is a local, dependency-light static analyzer. It separates file discovery, rule execution,
policy, data models, and output rendering so that new rules do not need to know about the CLI or
filesystem traversal.

```mermaid
flowchart TD
    A["CLI and policy"] --> B["Scanner"]
    B --> C["File discovery and decoding"]
    C --> D["Regex rules"]
    C --> E["Python AST rules"]
    C --> F["JSON / MCP rules"]
    E --> G["Taint engine"]
    D --> H["Normalized Finding"]
    E --> H
    F --> H
    G --> H
    H --> I["Suppressions and threshold"]
    I --> J["Text / JSON / SARIF"]
```

## Components

- `llmsafe.scanner.Scanner` owns traversal, decoding limits, excludes, suppressions, rule
  isolation, deduplication order, and aggregate results.
- `llmsafe.rules` contains independent rules that accept a path and UTF-8 content and yield
  normalized findings.
- `llmsafe.rules.dataflow` performs source-to-sink analysis within Python functions and across
  direct calls to local module-level helpers. Its project pass resolves a bounded set of local
  imports and propagates summaries across modules.
- `llmsafe.config` discovers and validates repository policy.
- `llmsafe.models` is the stable boundary between analysis and output.
- `llmsafe.sarif` maps normalized findings and evidence to SARIF 2.1.0.
- `llmsafe.cli` is a thin orchestration and exit-code layer.

## Taint-analysis algorithm

The `DataflowRule` analyzes the module body and every function:

1. Function arguments with trust-boundary names become user or model sources.
2. Known request objects and LLM SDK calls create additional sources.
3. Assignments, interpolation, containers, attribute access, calls, branches, loops, and exception
   branches propagate source sets through an environment keyed by variable name.
4. Calls are checked against code, process, SQL, HTTP, and dynamic-dispatch sinks.
5. Local function summaries map sink-relevant positional, keyword-only, variadic, and keyword
   parameters to those sinks.
6. Summaries are resolved to a fixed point so trust-boundary data can cross multiple local wrappers.
7. A finding records up to four contributing sources, the helper boundary, and the final sink as
   evidence.

Branch environments are merged conservatively. Reassigning a variable to an untainted expression
kills its previous taint in the current path.

## Local function summaries

Each module-level function is analyzed once with synthetic parameter sources. Only parameters that
reach a sensitive operation are retained in its summary. Repeated passes propagate terminal sink
information through chains of local direct-name calls. At a real call site, only tainted arguments
mapped to a sink-relevant parameter produce a finding; fixed arguments remain clean.

This design detects common agent wrappers without importing the scanned application. See the
[cross-file analysis design](cross-file-analysis.md) for project boundaries, supported import forms,
cycle handling, evidence paths, and deliberate limits.

## Rule failure isolation

A rule exception is recorded as a scan error instead of terminating the full scan. This protects
CI availability while preserving a non-zero exit code. Syntax-invalid Python is ignored by AST
rules but can still be inspected by text rules.

## Determinism

- Findings are sorted by severity, path, line, and rule ID.
- JSON and SARIF keys are sorted at serialization time.
- SARIF fingerprints exclude line numbers so alerts survive small line shifts.
- The scanner never performs network requests or imports the analyzed application.

## Extension contract

A rule implements one method:

```python
class Rule(Protocol):
    def scan(self, path: Path, content: str) -> Iterable[Finding]: ...
```

Rules should prefer structural parsing, emit stable IDs, avoid secret values in messages, include
actionable remediation, and provide vulnerable/safe regression tests.

Trusted consumers can add organization-specific rules through the bounded public
[`llmsafe.api` extension surface](extensions.md). Dynamic plugin discovery is deliberately excluded.

## Known architectural limits

- Cross-file summaries cover included local modules, explicit relative imports, aliases, and direct
  re-exports. Wildcard imports, dynamic imports, methods, and runtime import behavior are unresolved.
- No runtime values, dependency resolution, generated code, or authorization-server state.
- Python and MCP JSON receive structural analysis; other languages currently receive secret checks.
- Taint source names and SDK call markers are intentionally opinionated heuristics.
- Sanitizer correctness is domain-specific, so the current engine does not silently clear taint
  based on generic escaping calls.

These limits favor explainable results and give future work clear compatibility boundaries.
