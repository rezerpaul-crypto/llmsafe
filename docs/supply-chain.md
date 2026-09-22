# Supply-chain security

LLMSafe scans untrusted repositories, publishes a Python package, and can run inside other projects'
CI. Its source, workflow tokens, dependencies, release identity, and generated reports are therefore
separate security boundaries.

## Implemented controls

- Every third-party GitHub Action in repository workflows is pinned to a full 40-character commit
  SHA, with the reviewed major line retained as a comment.
- Artifact upload and download use reviewed Node.js 24 release lines; a workflow contract test
  rejects the older Node.js 20 major lines.
- Linux jobs use the explicit `ubuntu-24.04` runner image instead of the moving `ubuntu-latest`
  label; a workflow contract test prevents an unnoticed image migration.
- Checkout never persists the workflow token in the repository.
- Default workflow permission is `contents: read`; no job receives `contents: write`.
- Untrusted repository code generates SARIF in an unprivileged job. A separate job receives
  `security-events: write` only to upload the staged report.
- Fork pull requests do not receive the SARIF upload permission.
- PyPI publication uses Trusted Publishing with an environment gate and job-scoped OIDC
  `id-token: write`, not a long-lived package token.
- Package and release CI install an exact, transitive Python 3.12/Linux toolchain lock with SHA-256
  verification and binary-only resolution. Builds run without isolation so the backend cannot
  replace the reviewed `setuptools` version dynamically.
- Release CI checks the tag against package metadata, builds wheel and source distributions, runs
  Twine validation, and installs the wheel in a fresh environment.
- Dependabot monitors Python development dependencies and GitHub Actions weekly. Pytest 9 and newer
  are excluded with an explicit version boundary while LLMSafe supports Python 3.9; this avoids a
  grouped update bypassing a semantic-major filter on the open-ended `pytest>=7.4` requirement.
  Setuptools major updates are held separately. Compatible updates remain eligible.
- The repository has a security policy, deterministic tests, a self-scan, and an isolated local
  release-candidate build record.

Automated tests reject mutable Action references, persisted checkout credentials, broad write
permissions, missing dependency-update ecosystems, or removal of the Python 3.9 compatibility
guards for pytest and setuptools updates.

## Open hardening work

- Protect `main` with required CI checks, pull-request review, conversation resolution, deletion
  prevention, and force-push prevention. This is a repository setting, not a source-file claim.
- Decide on a maintainable cross-Python lock-and-hash strategy for contributor development
  dependencies. The release toolchain is locked separately because it has one fixed platform;
  ordinary development still spans Python 3.9 through 3.14.
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

## Updating the release toolchain

`requirements/release.in` contains the four direct release-tool pins. The checked-in
`requirements/release-linux-py312.txt` resolves their complete graph for the fixed Ubuntu 24.04,
Python 3.12 release job and requires binary artifacts with SHA-256 hashes.

Regenerate the lock with `uv 0.12.17`:

```bash
uv pip compile --python-version 3.12 \
  --python-platform x86_64-manylinux_2_17 \
  --generate-hashes --only-binary :all: --emit-build-options \
  requirements/release.in -o requirements/release-linux-py312.txt
```

Review every version change, run the workflow-security tests, and let the package CI job install and
build from the lock on its exact target runner before merging. The Python and pip supplied by the
pinned setup Action remain bootstrap trust boundaries.

## Trust limits

These controls reduce risk; they do not prove that dependencies, runners, PyPI, GitHub, or LLMSafe are
compromise-free. Remote repository settings must be audited separately because they can change without
a source commit.
