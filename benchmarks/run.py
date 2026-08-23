"""Run the checked-in benchmark manifest and report rule-level recall."""

import json
from pathlib import Path
from typing import Any, Dict, Optional

from llmsafe.scanner import Scanner


def run_benchmark(root: Optional[Path] = None) -> Dict[str, Any]:
    benchmark_root = root or Path(__file__).parent
    manifest = json.loads((benchmark_root / "manifest.json").read_text(encoding="utf-8"))
    cases = []
    expected_total = 0
    detected_total = 0
    for case in manifest["cases"]:
        expected = set(case["expected_rules"])
        result = Scanner().scan([benchmark_root / case["path"]])
        found = {finding.rule_id for finding in result.findings}
        missing = sorted(expected - found)
        unexpected = sorted(found - expected)
        expected_total += len(expected)
        detected_total += len(expected & found)
        cases.append(
            {
                "path": case["path"],
                "expected": sorted(expected),
                "found": sorted(found),
                "missing": missing,
                "unexpected": unexpected,
                "passed": not missing and not unexpected and not result.errors,
            }
        )
    recall = 1.0 if expected_total == 0 else detected_total / expected_total
    return {
        "cases": cases,
        "summary": {
            "cases": len(cases),
            "passed": sum(case["passed"] for case in cases),
            "expected_findings": expected_total,
            "detected_findings": detected_total,
            "rule_recall": recall,
        },
    }


def main() -> int:
    report = run_benchmark()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if all(case["passed"] for case in report["cases"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
