# Five-minute demo

This demonstration creates a temporary vulnerable agent, scans it, exports SARIF, applies a safe
fix, and proves the second scan is clean. It never needs an API key, model account, network request,
or cloud resource.

## Run it

From a cloned LLMSafe repository with Python 3.9 or newer:

```bash
python3 -m venv .demo-venv
.demo-venv/bin/python -m pip install llmsafe
.demo-venv/bin/python demo/run.py
```

On Windows, replace `.demo-venv/bin/python` with `.demo-venv\Scripts\python.exe`.

Contributors who already ran `python3 scripts/dev.py` can use:

```bash
.venv/bin/python demo/run.py
```

## What happens

1. The demo writes a temporary Python function that passes `user_input` to dynamic evaluation.
2. LLMSafe returns exit code `1` and reports both the dangerous API and source-to-sink flow.
3. LLMSafe writes a SARIF 2.1.0 report containing `PY001` and `FLOW001`.
4. The demo replaces execution with `json.loads`, representing a defined data format.
5. The second scan returns exit code `0` with no findings.

Expected final output:

```text
[1/3] Vulnerable agent detected
...
[2/3] SARIF generated with rules: FLOW001, PY001
[3/3] Fixed agent passes
Scanned 1 file(s), skipped 0; found 0 issue(s).
Demo passed: detect, export, fix, rescan.
```

The temporary workspace is deleted automatically. The example demonstrates deterministic scanner
behavior, not a claim that a clean scan proves an application secure. LLMSafe should run alongside
dependency scanning, general static analysis, review, and runtime controls.

## Manual equivalent

For your own application, the same loop is:

```bash
llmsafe agent.py
llmsafe agent.py --format sarif --output llmsafe.sarif
# replace dynamic execution with a parser and allow-listed operation
llmsafe agent.py
```

Exit code `1` means a finding reached the configured threshold. Exit code `2` means configuration,
input, or scanner processing failed; it must not be treated as a clean result.
