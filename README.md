# LLMSafe

[![CI](https://github.com/rezerpaul-crypto/llmsafe/actions/workflows/ci.yml/badge.svg)](https://github.com/rezerpaul-crypto/llmsafe/actions/workflows/ci.yml)
[![Code scanning](https://github.com/rezerpaul-crypto/llmsafe/actions/workflows/code-scanning.yml/badge.svg)](https://github.com/rezerpaul-crypto/llmsafe/actions/workflows/code-scanning.yml)
[![PyPI](https://img.shields.io/pypi/v/llmsafe.svg)](https://pypi.org/project/llmsafe/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-3776AB.svg)](pyproject.toml)

LLMSafe is an open-source static security scanner for AI-powered and agentic Python
applications. It traces user input and model-controlled data into dangerous capabilities such as
code execution, shells, SQL, outbound requests, and dynamic tool dispatch.

It runs locally. Source code is not uploaded to a model or external analysis service.

> **Status:** `v0.2.1` is the current stable release. `v0.3.0rc1` is available as a public pilot
> pre-release; LLMSafe provides reviewable security signals, not a guarantee that an AI system is
> secure.

## Why another security scanner?

Traditional Python scanners are good at finding dangerous APIs. Agentic applications add a
different question: **can untrusted user or model output reach that capability?**

```mermaid
flowchart LR
    A["User input"] --> C["Assignments and transforms"]
    B["Model output"] --> C
    C --> D["Shell / eval / SQL / HTTP / tool dispatch"]
    D --> E["Finding with source-to-sink evidence"]
```

LLMSafe combines focused API checks with AST-based dataflow and agent-framework rules:

```python
def run_agent(client, user_input):
    response = client.responses.create(input=user_input)
    generated_code = response.output_text
    return eval(generated_code)
```

The scanner reports both the dangerous `eval()` and the path from the model response to that
sink:

```text
agent.py:4:12: CRITICAL FLOW001 Untrusted data reaches code execution
  Untrusted or model-controlled data flows into eval(). Source: model, user.
  Trace 2:16: model source: client.responses.create
  Trace 1:23: user source: user_input
  Trace 4:12: reaches eval
  Fix: Replace dynamic execution with a typed parser and an allow-listed operation.
```

## Detection coverage

| Family | Rule IDs | Examples |
| --- | --- | --- |
| Dataflow | `FLOW001`–`FLOW005` | Model/user data reaching code, shell, SQL, URL, or tool dispatch |
| Agent tools | `AGENT001`–`AGENT003` | Python/shell tools, dangerous capability flags, disabled approval |
| Secrets | `SECRET001`–`SECRET005` | Provider keys, tokens, private keys, hard-coded credentials |
| Python | `PY001`–`PY004` | `eval`, `exec`, unsafe pickle and YAML deserialization |
| Shell | `SHELL001`–`SHELL002` | `os.system` and `subprocess(..., shell=True)` |
| Prompt trust | `LLM001` | Dynamic data interpolated into system/developer instructions |
| MCP | `MCP001`–`MCP003` | Shell launch, remote HTTP, wildcard tool permissions |

See the [complete rule catalog](docs/rules.md), [framework coverage matrix](docs/framework-coverage.md),
and [threat model](docs/threat-model.md).

Integrations can query the same catalog without parsing documentation:

```bash
llmsafe --list-rules
llmsafe --list-rules --format json
```

The versioned JSON output includes every stable ID, severity, family, description, and remediation.
See the [machine-readable integration contracts](docs/integration-contracts.md) for scan JSON, SARIF,
catalog, and exit-code compatibility.

Trusted internal tooling can add explicit organization-specific checks through the small
[`llmsafe.api` extension surface](docs/extensions.md); the CLI does not dynamically load plugins.

## Install

LLMSafe supports Python 3.9 and newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install llmsafe
```

For development:

```bash
git clone https://github.com/rezerpaul-crypto/llmsafe.git
cd llmsafe
python3 scripts/dev.py
```

For pipx, pre-commit, and reviewed-baseline adoption, see the
[local integration guide](docs/local-integration.md).

This creates an isolated environment and runs the same quality workflow as CI.

## Use the CLI

Scan the current repository:

```bash
llmsafe .
```

Scan selected paths and fail on medium-or-higher findings:

```bash
llmsafe src agent.py --fail-on medium --exclude "generated/**"
```

Generate machine-readable reports:

```bash
llmsafe . --format json --output reports/llmsafe.json
llmsafe . --format sarif --output reports/llmsafe.sarif
```

Exit codes are stable for automation:

| Code | Meaning |
| --- | --- |
| `0` | No finding at or above the selected threshold |
| `1` | At least one finding reached the selected threshold |
| `2` | Invalid configuration, missing target, or scan error |

## Five-minute demo

Run a complete vulnerable scan, SARIF export, safe fix, and clean rescan without credentials or
cloud resources:

```bash
.venv/bin/python demo/run.py
```

See the [demonstration walkthrough](docs/demo.md) for a clean-environment install and expected
output.

## Repository policy

Commit a `.llmsafe.toml` file:

```toml
[llmsafe]
exclude = ["generated/**", "vendor/**"]
fail_on = "high"
max_file_size = 1000000
disabled_rules = ["PY004"]
```

CLI options override or extend repository policy. Policy can also live under `[tool.llmsafe]` in
`pyproject.toml`. See [configuration](docs/configuration.md).

### Adopt LLMSafe without ignoring new risk

Existing repositories can review and commit a baseline of current findings:

```bash
llmsafe . --write-baseline .llmsafe-baseline.json
llmsafe . --baseline .llmsafe-baseline.json
```

The second command reports and fails only on findings not represented in the baseline. Matching is
line-independent, duplicate-aware, and deterministic so ordinary code movement does not create
noise while an additional dangerous operation is still reported. Baselines are review artifacts,
not permanent suppressions; see [incremental adoption](docs/baselines.md).

### Suppress one reviewed finding

Place a narrow suppression on the finding line or immediately above it:

```python
# llmsafe: ignore[PY001] -- expression is generated from a fixed internal grammar
result = eval(TRUSTED_EXPRESSION)
```

Prefer a rule-specific suppression over a bare `llmsafe: ignore`.

## GitHub Code Scanning

The repository includes a reusable composite action. A consumer workflow can scan, upload SARIF,
then enforce the configured threshold:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v7
  - uses: actions/setup-python@v7
    with:
      python-version: "3.12"
  - id: llmsafe
    continue-on-error: true
    uses: rezerpaul-crypto/llmsafe@v0.2.1
    with:
      path: .
      fail-on: high
  - if: always()
    uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: ${{ steps.llmsafe.outputs.sarif-file }}
  - if: steps.llmsafe.outcome == 'failure'
    run: exit 1
```

The action returns the SARIF path and the scanner's `exit-code`. The workflow uses only
`contents: read` and `security-events: write`; it does not use `pull_request_target` or require
repository write access. Pin the action to a released tag or, for immutable supply-chain pinning,
the full commit SHA for that release. See the [complete action contract](docs/github-action.md).

## Pre-commit

```yaml
repos:
  - repo: https://github.com/rezerpaul-crypto/llmsafe
    rev: v0.2.1
    hooks:
      - id: llmsafe
```

## Benchmark

The checked-in benchmark exercises vulnerable and safe agent boundaries:

```bash
python -m benchmarks.run
```

Current expectations cover 28 rule-level signals across direct, local-helper, and cross-framework code execution,
shell execution, SQL, SSRF, tool dispatch, prompt boundaries, high-impact tools, approval bypasses,
and MCP. This is a regression corpus—not an industry benchmark or a claim of real-world detection
rate. See the [benchmark methodology](docs/benchmark.md).

## How LLMSafe fits

| Tool category | Primary strength | LLMSafe relationship |
| --- | --- | --- |
| General Python SAST | Broad language and API security checks | Complementary; LLMSafe focuses on AI/agent trust boundaries |
| Pattern-rule engines | Highly customizable organizational rules | LLMSafe supplies opinionated agent rules without rule authoring |
| Dependency scanners | Known vulnerable packages and supply chain | Out of scope; run alongside LLMSafe |
| Runtime guardrails | Enforce live policy and monitor model/tool calls | Out of scope; LLMSafe reviews source and configuration before runtime |

Read the [architecture](docs/architecture.md) for implementation boundaries and tradeoffs.
The [supply-chain security](docs/supply-chain.md) page records implemented controls and open gaps.

## Contributing and security

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md) and the public
[roadmap](ROADMAP.md). The [governance policy](GOVERNANCE.md), [Code of
Conduct](CODE_OF_CONDUCT.md), and [support policy](SUPPORT.md) explain how decisions are made and
where to ask for help. Report vulnerabilities privately according to [SECURITY.md](SECURITY.md).

The complete contributor setup and quality suite is one command: `python3 scripts/dev.py`.

LLMSafe is released under the [MIT License](LICENSE).
