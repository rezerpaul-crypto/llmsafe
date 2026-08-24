import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_five_minute_demo_detects_exports_and_fixes() -> None:
    result = subprocess.run(
        [sys.executable, "demo/run.py"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "[1/3] Vulnerable agent detected" in result.stdout
    assert "[2/3] SARIF generated with rules: FLOW001, PY001" in result.stdout
    assert "[3/3] Fixed agent passes" in result.stdout
    assert "Demo passed: detect, export, fix, rescan." in result.stdout
