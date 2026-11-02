# Reproducible engineering quality gates

Inspect actual repository scripts and branch content before running commands. No command's presence in this file means it was executed or passed. Use a disposable virtual environment; never run untrusted target repository programs. Save only redacted logs and hashes, outside public source when necessary.

## Capture before editing

```bash
git status --short
git rev-parse --show-toplevel
git branch --show-current
git rev-parse HEAD
python3 --version
uname -a
```

Record exact PR base/head, dependency stacks, existing failing tests, CI state, OS/architecture, Python and LLMSafe versions. On Windows, use equivalent PowerShell commands. Stop before destructive changes if working tree has unrelated modifications.

## RED → GREEN → REVIEW

1. Reproduce the bug with a minimal fixture or actual *authorized local* code and exact expected signal.
2. Add vulnerable and safe tests; run focused pytest and demonstrate the initial failure.
3. Patch a bounded rule/analysis step; run the same tests and compare exact findings, not just pytest exit.
4. Verify the complete contributor workflow using the supported environment setup:
   - First setup: `python3 scripts/dev.py` (installs dependencies if necessary).
   - Existing environment: `python3 scripts/dev.py --check-only`.
   - If available on the branch, `python3 scripts/research_gaps.py --strict` for frozen research cases.
   - Performance-sensitive change: `python3 -m benchmarks.performance --modules 500 --budget-seconds 2` (record actual time and conditions).
5. For relevant CLI changes, explicitly test `python3 -m llmsafe --version`, JSON/SARIF output, rule catalog, a clean fixture (`0`), expected threshold finding (`1`), and scan/configuration error (`2`). A `0` is **not** proof the whole project is secure.
6. Compare repeat outputs at identical tool/target SHA with stable configuration; preserve deterministic paths, fingerprints, ordering and schema. For changed rule semantics, verify all existing regression signals and no new safe-case noise.
7. Check GitHub CI for every supported interpreter, Windows, packaging, and hosted macOS if that job is present. Test separately on the owner's macOS ARM64; CI-hosted macOS does **not** substitute for owner-device sign-off. Get an independent reviewer for high-impact analyzer changes.

## Fail-closed / blocked conditions

- Missing input, scan error, unreliable parser coverage, skipped critical scope or malformed machine output: report an incomplete analysis, not a clean bill of health.
- Coverage below repository gate; expected benchmark signals removed; previously safe tests newly noisy; cross-file evidence lost; scan results nondeterministic; unintended JSON v1 / SARIF contract change; runtime performance unacceptable: block merge readiness.
- Missing CI status, Mac evidence, actual test execution or human review: say `NOT RUN` / `NOT REVIEWED`, not PASS. A draft PR can document partial progress.
- No secrets, unconsented project code, or raw vulnerability evidence in public GitHub comments, issue bodies, CI artifacts, or sample customer reports.

## Required end-of-day verification record

```text
UTC/date:
Repository, base SHA, head SHA, branch/PR:
Trust-boundary scenario and smallest regression:
Before findings / after findings (IDs + rationale):
Positive and safe tests:
Focused pytest: PASS | FAIL | NOT RUN (command, output summary)
Full dev workflow: PASS | FAIL | NOT RUN
Research harness: PASS | FAIL | NOT APPLICABLE | NOT RUN
Performance: PASS | FAIL | NOT APPLICABLE | NOT RUN
CI / Windows / hosted macOS / owner macOS ARM64: each separately
JSON/SARIF / exit codes / secrets handling:
Reviewer and unresolved concerns:
Final disposition: DRAFT | REVIEW READY | BLOCKED
Next highest-impact task:
```
