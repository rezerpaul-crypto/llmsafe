# GitHub Action contract

The LLMSafe composite action installs the exact source revision referenced by `uses:`, runs one local
scan, and writes SARIF without uploading source code or contacting a model provider.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `.` | File or directory to scan |
| `fail-on` | `high` | Minimum severity that returns exit code 1 |
| `config` | empty | Explicit LLMSafe TOML policy path |
| `baseline` | empty | Reviewed baseline JSON path |
| `sarif-file` | `llmsafe.sarif` | SARIF output destination |

Paths are passed as individual shell arguments, including paths containing spaces. Invalid policy,
baseline, or CLI input returns exit code 2 rather than silently weakening the scan.

## Outputs and exit codes

| Output | Meaning |
| --- | --- |
| `sarif-file` | The requested SARIF destination, or empty if validation failed before a report existed |
| `exit-code` | `0` clean, `1` policy-level finding, or `2` usage/configuration error |

The scan step preserves LLMSafe's exit status after recording outputs. Use `continue-on-error: true`
when SARIF must be uploaded before a separate enforcement step.

The underlying JSON, SARIF, catalog, and exit-code behavior is defined in the
[integration contracts](integration-contracts.md).

## Minimal-permission workflow

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
  - if: always() && steps.llmsafe.outputs.sarif-file != ''
    uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: ${{ steps.llmsafe.outputs.sarif-file }}
      category: llmsafe
  - if: steps.llmsafe.outputs.exit-code != '0'
    run: exit 1
```

`security-events: write` is needed only for SARIF upload. The action itself needs repository contents
read access. Do not switch this workflow to `pull_request_target`; scans should not combine untrusted
pull-request code with elevated credentials.

## Pinning

Use a released semantic-version tag for readable updates. Use the full commit SHA corresponding to a
reviewed release when immutable action code is required. Do not point production workflows at a
development branch.

## Test coverage

Local tests exercise safe and failing scans, SARIF parsing, configuration, baselines, paths, outputs,
and exit-code preservation through the same shell entrypoint used by the composite action. Repository
CI also invokes `uses: ./` and verifies its outputs and generated SARIF on GitHub's runner.
