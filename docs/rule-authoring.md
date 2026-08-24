# Authoring a rule

This guide takes a contributor from a concrete risk to a reviewed LLMSafe rule. The checked-in
[`DebugAgentRule`](../examples/rules/debug_agent.py) is deliberately small enough to understand in
one sitting, while its [tests](../tests/test_rule_authoring_example.py) exercise the same quality
requirements as a built-in detection.

Organization-owned runners can execute reviewed custom rules through the public
[extension API](extensions.md) without modifying LLMSafe's built-in registry.

## 1. Define the security contract

Before writing code, state all four parts:

1. **Risk:** what attacker- or model-controlled behavior can cause harm?
2. **Signal:** what syntax or configuration proves enough of that behavior to report?
3. **Safe case:** what similar construction must remain quiet?
4. **Boundary:** what cannot be determined statically and must not be guessed?

For the worked example:

- Risk: agent debug output can expose prompts, tool arguments, or execution details.
- Signal: a Python call named `Agent` contains the literal keyword `debug=True`.
- Safe case: `debug=False` is not reported.
- Boundary: a variable such as `debug=setting` is not evaluated or guessed.

This example is instructional and is not registered as a built-in LLMSafe rule. A production rule
proposal still needs evidence that the pattern exists across relevant frameworks with acceptable
noise.

## 2. Implement the minimal rule interface

Every rule accepts a path and UTF-8 content and yields normalized findings:

```python
class Rule(Protocol):
    def scan(self, path: Path, content: str) -> Iterable[Finding]: ...
```

The worked example follows a predictable sequence:

1. Return early for unsupported file types.
2. Parse Python without importing or executing the target application.
3. Walk only the syntax nodes relevant to the risk.
4. Require an explicit structural signal.
5. Yield a `Finding` at the dangerous operation with actionable remediation.

Use helpers from `llmsafe.rules.ast_helpers` instead of duplicating parsing or call-name logic. A
syntax error should produce no result from an AST rule; text-oriented rules may still inspect the
file.

## 3. Choose stable metadata

A built-in rule needs a permanent ID, concise title, severity, family, description, and remediation
in `llmsafe/catalog.py`. IDs are public API: configuration, baselines, JSON, SARIF, and downstream
automation depend on them.

- Use `critical` for direct, high-confidence paths to severe impact.
- Use `high` for dangerous behavior with meaningful impact but remaining application context.
- Use `medium` for important hardening signals or lower-confidence impact.
- Use `low` sparingly for useful findings that should not normally fail CI.

Never raise severity to make a rule appear more important. Messages must not echo credentials,
private payloads, or unbounded source text.

## 4. Write the three required test classes

Every detection change must include:

- **Vulnerable:** the smallest realistic source that must produce the exact rule ID and location.
- **Safe:** the closest secure alternative, proving the rule is not broad keyword matching.
- **Edge:** aliases, dynamic values, comments/strings, malformed syntax, or unsupported files that
  define the detection boundary.

The example tests also assert remediation is present. For a data-flow rule, assert evidence steps
from source through helper boundaries to the reported sink.

## 5. Register a built-in rule

After the behavior and tests are accepted:

1. Add the implementation under `llmsafe/rules/`.
2. Export it from `llmsafe/rules/__init__.py`.
3. Add one instance to `llmsafe.scanner.DEFAULT_RULES`.
4. Add stable metadata to `llmsafe/catalog.py`.
5. Document the rule in [the catalog](rules.md).
6. Add a benchmark signal when it represents a core AI/agent boundary.
7. Update the changelog when the behavior will ship.

Catalog and SARIF tests reject drift between public metadata and findings. Do not reuse an existing
ID, silently change its meaning, or remove it without a documented compatibility decision.

## 6. Verify the complete contribution

Run the same workflow as CI:

```bash
python3 scripts/dev.py --check-only
```

A rule is ready for review only when lint, tests, coverage, benchmark, installed CLI, and self-scan
all pass. In the pull request, explain expected false positives, false negatives, framework
assumptions, and why a suppression is not the primary solution.

## Reviewer checklist

- [ ] The risk and attacker/model control are concrete.
- [ ] Structural or data-flow evidence is preferred over a broad keyword.
- [ ] Vulnerable, safe, and edge-case tests are present.
- [ ] The finding points to the dangerous operation.
- [ ] Metadata, severity, message, and remediation agree.
- [ ] No sensitive fixture value is committed or emitted.
- [ ] Benchmark and public documentation are updated when required.
- [ ] Known noise and unsupported cases are stated explicitly.
