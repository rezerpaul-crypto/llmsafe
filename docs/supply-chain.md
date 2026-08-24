# Supply-chain security

LLMSafe scans untrusted repositories, publishes a Python package, and can run inside other projects'
CI. Its source, workflow tokens, dependencies, release identity, and generated reports are therefore
separate security boundaries.

## Implemented controls

- Every third-party GitHub Action in repository workflows is pinned to a full 40-character commit
  SHA, with the reviewed major line retained as a comment.
- Checkout never persists the workflow token in the repository.
- Default workflow permission is `contents: read`; no job receives `contents: write`.
- Untrusted repository code generates SARIF in an unprivileged job. A separate job receives
  `security-events: write` only to upload the staged report.
- Fork pull requests do not receive the SARIF upload permission.
- PyPI publication uses Trusted Publishing with an environment gate and job-scoped OIDC
  `id-token: write`, not a long-lived package token.
- Release CI checks the tag against package metadata, builds wheel and source distributions, runs
  Twine validation, and installs the wheel in a fresh environment.
- Dependabot monitors Python development dependencies and GitHub Actions weekly.
- The repository has a security policy, deterministic tests, a self-scan, and an isolated local
  release-candidate build record.

Automated tests reject mutable Action references, persisted checkout credentials, broad write
permissions, or missing dependency-update ecosystems.

## Open hardening work

- Protect `main` with required CI checks, pull-request review, conversation resolution, deletion
  prevention, and force-push prevention. This is a repository setting, not a source-file claim.
- Decide and document a reviewed lock-and-hash strategy for release tooling and development
  dependencies. Direct version bounds alone are not a reproducible dependency graph.
- Add an official OpenSSF Scorecard workflow only after reviewing its permissions and pinning every
  Action by SHA.
- Produce and retain an SBOM and verifiable build provenance for release artifacts.
- Require or document signed release tags and a maintainer key/identity rotation process.
- Test restoration from a clean clone and verify published provenance from PyPI after each release.

## Scorecard is not Criticality Score

OpenSSF Scorecard measures security practices. OpenSSF Criticality Score estimates how critical a
project is from public usage and activity signals. Anthropic's Claude for Open Source criterion refers
to a Criticality Score of at least 0.4, not a good Scorecard result. LLMSafe must not present one as the
other.

## Updating pinned Actions

Dependabot may propose a new SHA. Review the upstream release and compare the old and new commits;
retain the human-readable version comment, run workflow contract tests, and merge through protected
`main`. Do not replace the SHA with a mutable branch or major tag merely to make updates easier.

## Trust limits

These controls reduce risk; they do not prove that dependencies, runners, PyPI, GitHub, or LLMSafe are
compromise-free. Remote repository settings must be audited separately because they can change without
a source commit.
