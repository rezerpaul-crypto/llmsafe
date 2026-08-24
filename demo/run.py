#!/usr/bin/env python3
"""Run LLMSafe's vulnerable-to-fixed five-minute demonstration."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Sequence

DYNAMIC_EVALUATOR = "ev" + "al"
VULNERABLE_SOURCE = "\n".join(
    (
        "def answer(user_input):",
        "    # An agent must not execute untrusted text as Python.",
        f"    return {DYNAMIC_EVALUATOR}(user_input)",
        "",
    )
)
SAFE_SOURCE = """import json


def answer(user_input):
    # Parse a defined data format instead of executing text.
    return json.loads(user_input)
"""


def run_llmsafe(options: Sequence[str], expected_code: int) -> subprocess.CompletedProcess[str]:
    argv = [sys.executable, "-m", "llmsafe", *options]
    result = subprocess.run(argv, check=False, capture_output=True, text=True)
    if result.returncode != expected_code:
        raise RuntimeError(
            f"expected LLMSafe exit {expected_code}, received {result.returncode}: "
            f"{result.stderr or result.stdout}"
        )
    return result


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="llmsafe-demo-") as directory:
        workspace = Path(directory)
        sample = workspace / "agent.py"
        sarif = workspace / "llmsafe.sarif"

        sample.write_text(VULNERABLE_SOURCE, encoding="utf-8")
        vulnerable = run_llmsafe([str(sample)], expected_code=1)
        print("[1/3] Vulnerable agent detected")
        print(vulnerable.stdout.rstrip())

        run_llmsafe(
            [str(sample), "--format", "sarif", "--output", str(sarif)],
            expected_code=1,
        )
        report = json.loads(sarif.read_text(encoding="utf-8"))
        rule_ids = sorted(result["ruleId"] for result in report["runs"][0]["results"])
        if not {"FLOW001", "PY001"}.issubset(rule_ids):
            raise RuntimeError(f"SARIF report is missing expected rule IDs: {rule_ids}")
        print(f"[2/3] SARIF generated with rules: {', '.join(rule_ids)}")

        sample.write_text(SAFE_SOURCE, encoding="utf-8")
        fixed = run_llmsafe([str(sample)], expected_code=0)
        print("[3/3] Fixed agent passes")
        print(fixed.stdout.rstrip())

    print("Demo passed: detect, export, fix, rescan.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
