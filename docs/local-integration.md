# Local integration

LLMSafe can be adopted without changing application dependencies or uploading source code. Choose
one installation path, review the first scan, and add a baseline only when existing findings cannot
be fixed in the same change.

## Run with pipx

Run the public release in an isolated environment:

```bash
pipx run --spec llmsafe==0.2.1 llmsafe . --fail-on high
```

Maintainers testing a local LLMSafe checkout can verify that exact source tree with:

```bash
pipx run --spec . llmsafe . --fail-on high
```

`pipx install llmsafe==0.2.1` is useful for repeated manual scans. Pinning keeps local results
reproducible; update the pin in a reviewed change.

## Run on every commit

```yaml
repos:
  - repo: https://github.com/rezerpaul-crypto/llmsafe
    rev: v0.2.1
    hooks:
      - id: llmsafe
```

The hook scans the repository once instead of receiving only changed filenames. That is necessary for
cross-module import and dataflow analysis. The default high-severity threshold can be changed with an
explicit `args` override in the consumer configuration.

Verify the hook before committing its configuration:

```bash
pre-commit try-repo https://github.com/rezerpaul-crypto/llmsafe llmsafe --all-files \
  --ref v0.2.1
```

## Adopt with a reviewed baseline

First capture the full result:

```bash
llmsafe . --format json --output llmsafe-first-scan.json
```

Fix confirmed issues where practical. If reviewed historical findings remain, write the baseline in a
separate change:

```bash
llmsafe . --write-baseline .llmsafe-baseline.json
llmsafe . --baseline .llmsafe-baseline.json --fail-on high
```

Commit the baseline and review every later change to it. A baseline acknowledges existing findings; it
does not mark them safe. New duplicate operations remain visible because matching is count-aware.

## Verification checklist

- The version is pinned and `llmsafe --version` is recorded in CI logs.
- The first JSON result is reviewed before a baseline is written.
- `.llmsafe-baseline.json` is committed, not ignored.
- A deliberately added high-severity test finding makes the local or pre-commit command fail.
- Cross-file scans receive a directory target, not an isolated changed file.
- Baseline updates are separated from unrelated feature changes.

See [configuration](configuration.md), [baselines](baselines.md), and the
[GitHub Action contract](github-action.md) for the matching CI setup.

## Candidate verification record

On 24 August 2026, `pre-commit try-repo` installed the local hook in an isolated environment and
passed an all-files run: 85 files selected, 0 findings, 0 errors, 0.18 seconds. An isolated
`pipx run --spec . llmsafe --version` installed the local package and returned `0.3.0rc1`. Automated
tests separately verify the directory scan contract and baseline/configuration forwarding.

These checks validate installation mechanics only. They are not external adoption or user evidence.
