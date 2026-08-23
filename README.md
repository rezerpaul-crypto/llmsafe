# LLMSafe

LLMSafe is an open-source static security scanner for AI-powered and agentic
applications. It catches risky patterns before they reach production and runs locally without
sending source code anywhere.

> **Status:** Early alpha (`v0.1.0`). Rules are deliberately focused and findings still require
> human review.

## What it detects

| Rule | Severity | Risk |
| --- | --- | --- |
| `SECRET001`–`SECRET005` | High–Critical | Provider keys, access tokens, private keys, and hard-coded credentials |
| `PY001`–`PY004` | Medium–Critical | Dynamic code execution and unsafe deserialization |
| `SHELL001`–`SHELL002` | High | Shell execution and `subprocess` calls with `shell=True` |
| `LLM001` | High | Dynamic user data interpolated into privileged system/developer prompts |
| `MCP001`–`MCP003` | High | Shell-launched servers, insecure remote HTTP, and wildcard tool permissions |

LLMSafe uses Python's abstract syntax tree for Python rules, parses MCP JSON structurally, and
uses narrow credential patterns. It reports the rule, location, severity, and a concrete fix.

## Quick start

LLMSafe requires Python 3.9 or newer and has no runtime dependencies.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
llmsafe .
```

Try it against the intentionally insecure samples:

```bash
llmsafe examples
```

Example output:

```text
examples/insecure_agent.py:9:5: HIGH SHELL002 Subprocess launched through a shell
  subprocess.run() is called with shell=True.
  Fix: Pass an argument list with shell=False and allow-list commands and arguments.
```

## Command-line usage

```text
llmsafe [PATH ...] [--format text|json] [--fail-on SEVERITY] [--exclude GLOB]
```

- One or more files or directories can be scanned; the current directory is the default.
- `--format json` produces stable, machine-readable output for CI integrations.
- `--fail-on` controls the exit threshold and defaults to `high`.
- `--exclude` accepts repeatable path globs.
- Files over 1 MB, binaries, common build folders, virtual environments, and `.git` are skipped.

Exit codes are designed for automation:

| Code | Meaning |
| --- | --- |
| `0` | No finding at or above the selected threshold |
| `1` | At least one finding reached the selected threshold |
| `2` | A target was missing or a scan error occurred |

### Suppressing a reviewed finding

Put a narrowly scoped comment on the finding's line or immediately above it:

```python
# llmsafe: ignore[PY001] -- input is a hard-coded arithmetic expression
result = eval(TRUSTED_EXPRESSION)
```

Multiple rule IDs can be comma-separated. A bare `llmsafe: ignore` suppresses every finding on
that line and should be avoided unless there is no narrower option.

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
ruff check .
pytest --cov=llmsafe --cov-report=term-missing
```

The CI workflow tests Python 3.9 and 3.12, runs Ruff, and enforces at least 85% coverage.

## Design principles

- **Local-first:** scanned source never leaves the machine.
- **Useful by default:** no required configuration or runtime packages.
- **Explainable:** every result maps to a stable rule ID and remediation.
- **Conservative:** prefer focused, reviewable signals over a large noisy rule set.
- **Agent-aware:** prioritize trust boundaries around prompts, tools, shell access, and MCP.

## Scope and limitations

LLMSafe is a lightweight static scanner, not a sandbox, penetration test, dependency audit, or
guarantee that an AI system is secure. It cannot understand every data flow or runtime policy.
Treat findings as review prompts and combine LLMSafe with least-privilege design, secret scanning,
dependency scanning, tests, monitoring, and human security review.

## Contributing and security

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Please report vulnerabilities
privately as described in [SECURITY.md](SECURITY.md).

LLMSafe is released under the [MIT License](LICENSE).
