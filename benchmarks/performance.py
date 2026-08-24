"""Repeatable local performance corpus for project-level dataflow."""

import argparse
import json
import tempfile
from pathlib import Path
from time import perf_counter
from typing import Any, Dict

from llmsafe.scanner import Scanner


def _write_corpus(root: Path, module_count: int) -> None:
    package = root / "generated_agent"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    for index in range(module_count):
        path = package / f"module_{index:04d}.py"
        if index == module_count - 1:
            content = "def forward(value):\n    return eval(value)\n"
        else:
            next_module = f"module_{index + 1:04d}"
            content = (
                f"from .{next_module} import forward as next_step\n\n"
                "def forward(value):\n"
                "    return next_step(value)\n"
            )
        path.write_text(content, encoding="utf-8")
    (root / "app.py").write_text(
        "from generated_agent.module_0000 import forward\n\n"
        "def handle(user_input):\n"
        "    return forward(user_input)\n",
        encoding="utf-8",
    )


def run_performance(module_count: int = 500) -> Dict[str, Any]:
    """Generate and scan a worst-case linear cross-module call chain."""

    if module_count < 1:
        raise ValueError("module_count must be positive")
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        _write_corpus(root, module_count)
        started = perf_counter()
        result = Scanner().scan([root])
        elapsed = perf_counter() - started
    flow_findings = [item for item in result.findings if item.rule_id.startswith("FLOW")]
    return {
        "elapsed_seconds": round(elapsed, 6),
        "errors": len(result.errors),
        "flow_findings": len(flow_findings),
        "generated_modules": module_count,
        "scanned_files": result.scanned_files,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--modules", type=int, default=500)
    parser.add_argument("--budget-seconds", type=float, default=2.0)
    arguments = parser.parse_args()
    report = run_performance(arguments.modules)
    report["budget_seconds"] = arguments.budget_seconds
    report["within_budget"] = report["elapsed_seconds"] < arguments.budget_seconds
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["within_budget"] and not report["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
