# Validation of the technical research handoff

Recorded: 2026-10-23. Runtime: Linux x86_64, Python 3.12.14.
This is not a macOS execution claim.

## Original scanner baseline

- Repository: rezerpaul-crypto/llmsafe.
- Scanner revision: c761627ad224a6f540d7ae6f06d2c076f426a6a6.
- Original tree contents: 127 blobs verified against Git blob hashes.
- Current source package: 0.3.0rc1.
- Full established contributor workflow: passed.
- Existing tests: 158 passed, 89.72% coverage; threshold 85% retained.
- Curated benchmark: 21/21 cases, 37/37 expected signals, no unexpected signals.
- Original repository self-scan: 106 selected files, no findings, no errors.
- Initial performance run: 500 generated modules, 502 selected files,
  0.215337 seconds, one cross-file finding, no errors, within the existing two-second budget.

PR #44 was open and unmerged when inspected; its documented validation is
not counted as main validation.

## Research additions

- Added a source-only, opt-in harness and 18 focused acceptance inputs.
- Added six guard tests for non-execution, focused-signal isolation and path confinement.
- Full contributor workflow with the additions: 164 tests passed, 89.72% coverage.
- Curated 21-case benchmark still passes unchanged.
- Self-scan at that checkpoint: 114 files, no findings and no errors.
- The Mac wrapper's --check-only path was run end to end on Linux.
- bash syntax validation passed; the wrapper uses Bash 3-compatible constructs.
- Focused cases: 8 expectations met, 10 intentional future acceptance gaps.
- The default discovery run exits 0. The same inputs with --strict exit 1.
- The follow-up performance run returned 0.247494 seconds for 502 selected files.
  These are separate single runs, not a statistical speed comparison.

Executed commands include:

```bash
.venv/bin/python scripts/dev.py --check-only
.venv/bin/python -m pytest tests/test_research_gaps.py -q
bash -n scripts/mac-research-check.sh
bash scripts/mac-research-check.sh --check-only
.venv/bin/python scripts/research_gaps.py --strict --json
```

## Scope

No production scanner rule, rule ID, public schema, supported Python version,
release version or CI policy was changed by this handoff.
The proposed packages A-J are not implemented here. No competitor was executed.
No target fixture was imported or run, no MCP server was launched, and no release
or main-branch merge is included. Future Mac runs record their actual checkout
and working-tree status under build/research/2026-10-23/.

The PDF was rendered to page images and visually checked. Its sources point
to the same primary documentation indexed in sources.json.
