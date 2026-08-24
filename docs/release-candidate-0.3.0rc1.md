# LLMSafe 0.3.0rc1 release-candidate record

Date prepared: 24 August 2026

Status: published as a public pilot pre-release on GitHub and PyPI; stable `v0.3.0` remains gated.

## Candidate scope

- Project-level Python dataflow through selected local modules.
- Explicit relative and absolute imports, aliases, direct re-exports, and safe cycles.
- Cross-file JSON and SARIF evidence locations.
- Current vulnerable/safe fixtures for five agent framework families.
- Versioned JSON, SARIF, catalog, and exit-code integration contracts.
- Tested composite GitHub Action, pre-commit path, pipx path, and bounded custom-rule API.
- Worklist-based project analysis with explicit performance and symlink boundaries.
- SHA-pinned GitHub Actions, least-privilege SARIF upload, and OIDC release workflow.
- Contributor workflow, rule-authoring example, and a credential-free five-minute demo.

## Quality gate

- Ruff: passed.
- Tests and coverage: 91 passed; 89.06% coverage, above the 85% gate.
- Curated benchmark: 15/15 cases; 28/28 expected signals; 100% corpus recall.
- Self-scan: 0 findings, 0 errors across 95 selected files.
- Performance corpus: one cross-file flow through a generated 500-module chain in 0.085693 seconds,
  below the 2-second budget, with 502 files scanned and no errors.
- Repository validation: 8 YAML files and 11 JSON files parsed; local links in 33 Markdown files
  resolved; `git diff --check` passed.
- Isolated wheel and source build: passed.
- Twine package check: passed for both artifacts.
- Clean Python 3.9 environment: wheel plus declared dependency installed; `llmsafe --version`
  returned `0.3.0rc1`.

Artifact hashes from the local candidate build:

- Wheel SHA-256: `ab2e6aff08d7a9ab171b5e7ba3371a23abbc65c971b2db147f2c57d392112bf9`
- Source SHA-256: `52ff54dcc71eca6889d225d942cfeb654893ea9257bcad15ca63f53927253d55`

Verified artifacts published by the OIDC trusted-publishing workflow:

- Wheel: `llmsafe-0.3.0rc1-py3-none-any.whl` (SHA-256
  `bd8326e80d9d06e87952f1cb56aaad1dd5a88820a670589ee6c921710ae0333f`)
- Source: `llmsafe-0.3.0rc1.tar.gz` (SHA-256
  `4db874d4f876d6b1fee0c852ef3aac833bd127e5367c4398dd952d86ea3505e2`)
- GitHub pull request: [#12](https://github.com/rezerpaul-crypto/llmsafe/pull/12)
- GitHub pre-release: [v0.3.0rc1](https://github.com/rezerpaul-crypto/llmsafe/releases/tag/v0.3.0rc1)
- PyPI release: [llmsafe 0.3.0rc1](https://pypi.org/project/llmsafe/0.3.0rc1/)
- Release workflow: [run 32713591285](https://github.com/rezerpaul-crypto/llmsafe/actions/runs/32713591285)

## Pilot gate

- Confirmed active pilot testers: 0.
- Required by the roadmap before a stable release: at least 3.
- Day-14 stretch target: 5 concrete pilot scenarios.

The technical candidate may be built and inspected locally, but it must not become stable `v0.3.0`
until at least one external pilot reproduces a run and no critical defect remains. No person or
project is counted without explicit acceptance.

## Publication decision

**Go for the public pilot pre-release.** The candidate passed its local and GitHub CI gates and was
published as `v0.3.0rc1` for external reproduction.

**No-go for stable `v0.3.0`.** At least one external pilot must reproduce a run and no critical
defect may remain. This is a quality gate, not permission to contact prospects automatically.
