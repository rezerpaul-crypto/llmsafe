import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_pre_commit_hook_scans_the_project_graph_once() -> None:
    hook = (PROJECT_ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8")

    assert "entry: llmsafe" in hook
    assert "pass_filenames: false" in hook
    assert "always_run: true" in hook
    assert "require_serial: true" in hook
    assert 'args: [".", "--fail-on", "high"]' in hook


def test_documented_local_scan_contract_is_executable() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "llmsafe", ".", "--fail-on", "high"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0
    assert "errors" not in completed.stderr.lower()
