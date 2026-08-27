# Cross-file analysis design

This document defines LLMSafe's project-level Python analysis boundary. The implementation remains
static and local: scanned code is parsed but never imported or executed.

## Project boundary

Only UTF-8 Python files already selected by the scanner belong to the project graph. An import is
resolved only when its target is among those files. Installed dependencies, namespace-package search
paths, dynamic imports, import hooks, and runtime changes to `sys.path` remain outside the graph.

For a scanned directory, module names are derived from paths below that directory. If the directory
itself is a package, its parent becomes the module root. `__init__.py` represents its package name.

## Import graph

The resolver supports:

- absolute and explicit relative imports;
- `from module import function as alias`;
- `import module as alias` followed by `alias.function()`;
- direct function re-exports through an included module or `__init__.py`;
- module and import cycles without recursive execution.

Wildcard imports, conditional import semantics, assignments that replace an imported name, classes,
methods, callable objects, and dynamic attribute construction are not resolved.

## Summary propagation

Each module-level function receives a summary of which parameters can reach code, process, SQL, URL,
or dynamic-dispatch sinks and which parameter or intrinsic trust-boundary sources influence its
return value. The analyzer repeatedly propagates those summaries through resolved local calls until
no summary changes. A dependency worklist ensures an import or call cycle cannot cause recursive
execution.

At a real call site, only tainted arguments mapped to sink-relevant parameters create a finding. Fixed
arguments remain clean even when the imported helper contains a sensitive primitive. Likewise, a
fixed helper return remains clean even when another helper argument is tainted; parameter-selective
and transitive returns preserve only the relevant source set.

## Evidence path

The primary finding location is the caller where untrusted data reaches the terminal operation. A
related evidence location points to a sink in another module when the helper performs that operation.
Sources created inside an imported helper also retain that source file. JSON includes the evidence
path only for cross-file steps; SARIF renders it as the related artifact URI.

## Performance budget

The release-candidate target is to scan a generated corpus of 500 small Python modules, including the
project pass, in under 2 seconds on the documented development machine. The benchmark command and raw
result must be recorded before release. This is an engineering budget, not a universal performance
promise; repository size, file size, and function count materially affect runtime.

Run the deterministic worst-case linear call-chain corpus with:

```bash
python -m benchmarks.performance --modules 500 --budget-seconds 2
```

The measured result and environment are recorded in the [performance report](performance.md).

## Security and correctness limits

Resolution is intentionally conservative. Unknown or ambiguous imports do not receive guessed
summaries. This avoids attributing a local sink to an unrelated dependency but can produce false
negatives for dynamic Python patterns. Cross-file support does not infer sanitizers or prove that an
authorization check is correct.
