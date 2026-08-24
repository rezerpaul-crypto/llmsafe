# Performance report

Date: 24 August 2026

Environment: macOS 26.4 on arm64, Python 3.9.6. Results are local measurements, not universal
hardware guarantees.

## Project-analysis corpus

The repeatable corpus generates one package containing 500 small modules in a linear import and call
chain. The last module calls `eval()`; a root application passes `user_input` into the first module.
This deliberately stresses summary propagation because the terminal sink is 500 calls away.

Command:

```bash
python -m benchmarks.performance --modules 500 --budget-seconds 2
```

Result after worklist propagation:

| Measure | Result |
| --- | ---: |
| Selected files | 502 |
| Cross-file findings | 1 |
| Scan errors | 0 |
| Elapsed time | 0.093989 seconds |
| Budget | under 2 seconds |

The initial whole-project fixed-point pass took 3.544285 seconds on the same corpus. Replacing full
rescans with a dependency worklist reduced this measurement by about 37.7 times while preserving the
same finding. The checked-in test uses a smaller corpus for CI correctness; the 500-module command is
the explicit performance gate.

## LLMSafe repository scan

The repository itself is also scanned in the standard contributor workflow. The release-candidate
run selected 77 files and returned zero findings and zero scan errors. This is a self-scan, not an
independent real-world corpus and therefore is not presented as adoption evidence.

## File-selection hardening

LLMSafe already excludes common VCS, dependency, cache, build, and virtual-environment directories.
The candidate also skips symbolic-link files, preventing a link inside the selected tree from causing
an unexpected read outside that tree.

## Limits

The synthetic chain measures a controlled worst case for summary distance, not parsing of very large
files, monorepo path diversity, or real framework complexity. Later opt-in benchmarks must record
repository revisions, consent, privacy handling, raw timing, and classification methodology.
