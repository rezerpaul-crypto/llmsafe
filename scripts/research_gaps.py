#!/usr/bin/env python3
"""Reproduce focused LLMSafe research cases without executing fixture code."""

from __future__ import annotations

import argparse
import json
import platform
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CASES = PROJECT_ROOT / "benchmarks/research/2026-10-23/cases.json"


def load_cases(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(data, dict)
        or data.get("schema_version") != 1
        or not isinstance(data.get("cases"), list)
    ):
        raise ValueError("Expected research case schema 1")
    seen = set()
    for case in data["cases"]:
        if not isinstance(case, dict) or not isinstance(case.get("id"), str):
            raise ValueError("Every case needs an id")
        if case["id"] in seen:
            raise ValueError("Duplicate case id")
        seen.add(case["id"])
        if not isinstance(case.get("expected"), bool):
            raise ValueError("Expected must be boolean")
        if not isinstance(case.get("focus"), str):
            raise ValueError("Every case needs a focus")
        files = case.get("files")
        if not isinstance(files, dict) or not files:
            raise ValueError("Every case needs source files")
        for name, source in files.items():
            normalized = str(name).replace("\\", "/")
            parts = normalized.split("/")
            if (
                normalized.startswith("/")
                or any(part in {"", ".", ".."} or ":" in part for part in parts)
                or not isinstance(source, str)
            ):
                raise ValueError("Fixture paths must remain inside the temporary case directory")
    return data


def run_cases(data: Dict[str, Any]) -> Dict[str, Any]:
    # Import our analyzer only. Target files are written and parsed, never imported or executed.
    sys.path.insert(0, str(PROJECT_ROOT))
    from llmsafe import __version__
    from llmsafe.api import scan_paths

    rows: List[Dict[str, Any]] = []
    for case in data["cases"]:
        with tempfile.TemporaryDirectory(prefix="llmsafe-research-") as directory:
            root = Path(directory)
            for name, source in case["files"].items():
                path = root / name.replace("\\", "/")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(source, encoding="utf-8")
            result = scan_paths([root])
            diagnostic_count = len(getattr(result, "diagnostics", ()))
            observed = (
                bool(result.errors) or bool(diagnostic_count)
                if case["focus"] == "diagnostic"
                else any(finding.rule_id == case["focus"] for finding in result.findings)
            )
            rows.append(
                {
                    "id": case["id"],
                    "label": case.get("label", case["id"]),
                    "group": case.get("group", "unspecified"),
                    "focus": case["focus"],
                    "expected": case["expected"],
                    "observed": observed,
                    "passed": observed == case["expected"],
                    "all_rule_ids": sorted({item.rule_id for item in result.findings}),
                    "errors": len(result.errors),
                    "diagnostics": diagnostic_count,
                    "error_messages": [item.message for item in result.errors],
                }
            )
    return {
        "schema_version": 1,
        "scanner_version": __version__,
        "reference_commit": data.get("reference_commit"),
        "python": platform.python_version(),
        "platform": platform.system(),
        "machine": platform.machine(),
        "note": data.get("purpose"),
        "summary": {
            "cases": len(rows),
            "matched": sum(row["passed"] for row in rows),
            "gaps": sum(not row["passed"] for row in rows),
        },
        "cases": rows,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--output", type=Path, help="Write the full result as JSON")
    parser.add_argument(
        "--json", action="store_true", help="Print JSON instead of the compact table"
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 if a focused acceptance expectation is not met",
    )
    args = parser.parse_args(argv)
    try:
        result = run_cases(load_cases(args.cases))
        rendered = json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
    except (OSError, ValueError, ImportError) as exc:
        print(f"Research harness error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(rendered, end="")
    else:
        print("Focused acceptance cases; this is not a general accuracy benchmark.")
        for row in result["cases"]:
            status = "PASS" if row["passed"] else "GAP "
            print(
                f"{row['id']:3} {status} {row['focus']:10} "
                f"expected={str(row['expected']):5} observed={str(row['observed']):5} "
                f"{row['label']}"
            )
        summary = result["summary"]
        print(
            f"{summary['matched']}/{summary['cases']} focused expectations met; "
            f"{summary['gaps']} gaps."
        )
    return 1 if args.strict and result["summary"]["gaps"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
