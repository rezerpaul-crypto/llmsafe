# Incremental adoption with baselines

A baseline lets an existing project introduce LLMSafe without treating every historical finding as
a new CI failure. It records reviewed findings while leaving new findings visible and enforceable.

## Create and review a baseline

Run LLMSafe from the repository root:

```bash
llmsafe . --write-baseline .llmsafe-baseline.json
```

The command scans normally, writes the baseline, and exits successfully when the scan itself has no
errors. Review both the terminal findings and the generated JSON before committing it. A baseline
entry is an acknowledgement that the finding already exists—not a statement that the code is safe.

Do not add `.llmsafe-baseline.json` to `.gitignore`. Changes to the file should receive the same
review as other security policy changes.

## Enforce only new findings

Use the CLI directly:

```bash
llmsafe . --baseline .llmsafe-baseline.json --fail-on high
```

Or configure the path relative to `.llmsafe.toml` or `pyproject.toml`:

```toml
[llmsafe]
baseline = ".llmsafe-baseline.json"
fail_on = "high"
```

The composite GitHub Action accepts the same policy explicitly:

```yaml
- uses: rezerpaul-crypto/llmsafe@v0.2.1
  with:
    path: .
    baseline: .llmsafe-baseline.json
    fail-on: high
```

## Matching guarantees

Each entry contains a SHA-256 identity derived from the rule, repository-relative file path, title,
and stable message. Line numbers remain in the JSON for review but are not part of the identity, so
adding unrelated lines does not invalidate the baseline.

Matching is count-aware. If a file has one baselined `eval` finding and a change adds a second one,
only one is matched and the additional finding remains active. Baseline files are size-limited and
strictly validated; malformed, missing, or unsupported baseline documents stop the scan with exit
code 2 instead of silently weakening enforcement.

## Reduce the baseline over time

When a finding is fixed, regenerate the baseline in a focused pull request and confirm that its
entry disappeared. Avoid regenerating a baseline together with unrelated feature work: that makes
newly accepted risk difficult to spot in review.

Inline `llmsafe: ignore[RULE_ID]` comments remain the better choice for a narrow, intentional false
positive because the justification stays next to the code. Baselines are intended for migration of
an existing finding set.
