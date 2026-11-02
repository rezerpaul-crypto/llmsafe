# Container value and mutation acceptance — November 2, 2026

This is a bounded follow-up to draft PR #61, pinned base
`f0bd7d8a230fa4778781f243955a2b6b661f12f7`. It is not release approval.

## Reproduced problem and change

The base loses source provenance in an ordinary value extraction:

```python
def handle(user_input):
    box = {"command": user_input}
    selected = box["command"]
    return eval(selected)
```

The base reports no FLOW001; the fixed analyzer reports FLOW001 at the terminal
call with the original parameter evidence. Scalar provenance is stored separately
from nested path references, so an overwrite of `box["command"]` cannot erase a
previously extracted scalar. Safe sibling reads remain quiet.

The base also misses writes observed through another name after `alias |= {...}`
and direct `alias.__setitem__(key, value)`. These now modify the shared dictionary
state. Known-key overwrites remain precise; unknown keys/mappings, multiple
possible receivers and branch rebinding remain conservative. A possible unknown
receiver cannot justify treating a method's return as the built-in `None` result.

`update()` and `|=` now share an argument-snapshot model: evaluate all key/value
and keyword expressions, retain untrusted keys, then apply field writes. Unknown
iterable pairs are not claimed to have precise per-key summaries.

## Verification

Environment: Linux x86_64, Python 3.12.14, isolated `.venv`. Commands:

```bash
.venv/bin/python scripts/dev.py --current --check-only
.venv/bin/python scripts/research_gaps.py --strict
.venv/bin/python -m benchmarks.performance --modules 500 --budget-seconds 2
```

- The first regression run before product changes reproduced 19 failing cases
  across new local and project-level tests. Additional adversarial branch tests
  exposed unsafe assumptions about receiver rebinding; those were corrected too.
- 32 added tests cover source evidence, scalar snapshots, selected safe siblings,
  conditional/multiple receivers, unknown mappings, iterable pairs, mutator return
  values, evaluation order and cross-file scalar returns/process sinks.
- Full contributor checks on the candidate: **277 tests passed**, **91.49% branch-aware
  coverage**, Ruff passed, **21/21 curated cases**, **37/37 expected signals**, and
  self-scan with no findings/errors. The frozen research harness passes **18/18**;
  the generated 500-module scan took **0.196097s** against the local 2s budget.
- JSON and SARIF reports were byte-identical across repeated scans of the same
  synthetic source, with the expected exit code 1. Two concurrent strict research
  runs both passed 18/18 with identical results and no temporary-path collisions.
- Source distribution/wheel build and `twine check` pass using the hash-locked
  release toolchain. The wheel was installed into a fresh external venv, where its
  CLI and the repaired alias-to-execution flow were verified outside the checkout.
- CI now requires **all 18** frozen research expectations on every Linux Python
  matrix version, Windows and hosted macOS, replacing macOS's eight-case subset
  assertion. Fixtures and their expectations are unchanged.

Exact PR head and CI logs are authoritative. No target code is imported/executed;
no public rule IDs, JSON v1/SARIF schemas or release version are changed.

## Known false negatives requiring a separate heap-model increment

These synthetic sources were parsed, not executed. Both still miss the expected
FLOW001 and must not be advertised as covered:

```python
def handle(user_input):
    box = {"inner": {"command": "1+1"}}
    box["inner"].update(command=user_input)
    return eval(box["inner"]["command"])
```

```python
def handle(user_input):
    box = {"inner": {"command": user_input}}
    inner = box["inner"]
    box["inner"] = {"command": "1+1"}
    return eval(inner["command"])
```

The first also applies to a nested path alias followed by `inner.update(...)`.
The second requires preserving the identity of a detached nested object, not
merely its current path. Arbitrary external mutation and interprocedural
container writes remain unsupported as previously documented.

## Next acceptance owner

Engineering: add identity-aware bounded nested objects and nested mutator
summaries with safe sibling, detached-alias and branch tests in a separate draft.
Independent reviewer and owner: complete the human security review and actual
Apple Silicon Mac checks tracked by issue #62. Hosted macOS is separate evidence.
No merge, release or Paid GO follows from these internal results.
