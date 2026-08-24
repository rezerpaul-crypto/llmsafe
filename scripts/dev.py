#!/usr/bin/env python3
"""Create an LLMSafe development environment and run every contributor check."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MINIMUM_PYTHON = (3, 9)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Set up LLMSafe and run lint, tests, benchmark, CLI smoke test, and self-scan.",
    )
    parser.add_argument(
        "--venv",
        type=Path,
        default=Path(".venv"),
        help="virtual environment path relative to the repository (default: .venv)",
    )
    parser.add_argument(
        "--current",
        action="store_true",
        help="install into and check the current environment; intended for isolated CI jobs",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="skip installation and run checks with the existing environment",
    )
    return parser.parse_args(argv)


def virtualenv_python(venv: Path) -> Path:
    executable = Path("Scripts/python.exe") if os.name == "nt" else Path("bin/python")
    return venv / executable


def run_step(label: str, argv: Sequence[str]) -> None:
    print(f"\n==> {label}", flush=True)
    print("    " + " ".join(argv), flush=True)
    subprocess.run(argv, cwd=PROJECT_ROOT, check=True)


def prepare_python(venv: Path, use_current: bool, check_only: bool) -> Path:
    if use_current:
        python = Path(sys.executable)
    else:
        resolved_venv = venv if venv.is_absolute() else PROJECT_ROOT / venv
        python = virtualenv_python(resolved_venv)
        if not python.exists() and check_only:
            raise RuntimeError(
                f"development environment not found at {resolved_venv}; run without --check-only"
            )
        if not python.exists():
            run_step(
                f"Create development environment with Python {sys.version_info.major}."
                f"{sys.version_info.minor}",
                [sys.executable, "-m", "venv", str(resolved_venv)],
            )

    if not check_only:
        run_step(
            "Update the packaging installer",
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--upgrade",
                "pip>=23.1",
            ],
        )
        run_step(
            "Install LLMSafe and development tools",
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--editable",
                ".[dev]",
            ],
        )
    return python


def run_checks(python: Path) -> None:
    executable = str(python)
    run_step("Lint", [executable, "-m", "ruff", "check", "."])
    run_step(
        "Tests and coverage",
        [executable, "-m", "pytest", "--cov=llmsafe", "--cov-report=term-missing"],
    )
    run_step("Curated security benchmark", [executable, "-m", "benchmarks.run"])
    run_step("Installed CLI smoke test", [executable, "-m", "llmsafe", "--version"])
    run_step("LLMSafe self-scan", [executable, "-m", "llmsafe", ".", "--format", "json"])


def main(argv: Sequence[str] | None = None) -> int:
    if sys.version_info < MINIMUM_PYTHON:
        required = ".".join(str(part) for part in MINIMUM_PYTHON)
        print(f"LLMSafe development requires Python {required} or newer.", file=sys.stderr)
        return 2

    args = parse_args(argv)
    try:
        python = prepare_python(args.venv, args.current, args.check_only)
        run_checks(python)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"\nDevelopment workflow failed: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError) and error.returncode:
            return error.returncode
        return 1

    print("\nLLMSafe development workflow passed.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
