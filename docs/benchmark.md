# Benchmark methodology

The LLMSafe benchmark is a checked-in regression corpus, not an external industry benchmark.
Its purpose is to make rule behavior measurable and prevent silent detection regressions.

## Corpus

`benchmarks/manifest.json` declares every case and the exact set of expected rule IDs:

- `vulnerable_agent.py` combines a privileged prompt, LLM response, code execution, shell command,
  SQL construction, outbound URL, dynamic tool dispatch, Python REPL tool, and disabled approval.
- `safe_agent.py` uses an allow-listed topic, parameterized SQL, an argument-list subprocess, and
  fixed tool lookup.
- `insecure_mcp.json` contains a shell-launched remote HTTP server with wildcard tool access.

## Metric

The runner calculates rule-level recall:

```text
detected expected rule IDs / expected rule IDs
```

A case fails if an expected rule is missing, an unexpected rule appears, or scanning returns an
error. Safe cases therefore act as coarse false-positive regressions.

Run it with:

```bash
python -m benchmarks.run
```

## Current result

- Cases: 3/3 passing
- Expected rule signals: 13
- Detected expected rule signals: 13
- Rule-level recall on this corpus: 100%

## Interpretation limits

The corpus is small, authored with knowledge of the rules, and does not estimate real-world recall
or false-positive rate. A result of 100% means implementation and expectations agree. It does not
mean LLMSafe finds every agent vulnerability.

Future benchmark additions should come from minimized real patterns, include a safe counterpart,
and explain the trust boundary under test.
