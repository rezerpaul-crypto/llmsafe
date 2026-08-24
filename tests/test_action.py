import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from llmsafe.cli import main

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ACTION_RUNNER = PROJECT_ROOT / "scripts" / "run-action.sh"


def run_action(
    target: Path,
    sarif: Path,
    output: Path,
    fail_on: str = "high",
    config: Path = None,
    baseline: Path = None,
):
    environment = os.environ.copy()
    environment.update(
        {
            "GITHUB_OUTPUT": str(output),
            "LLMSAFE_INPUT_BASELINE": str(baseline) if baseline else "",
            "LLMSAFE_INPUT_CONFIG": str(config) if config else "",
            "LLMSAFE_INPUT_FAIL_ON": fail_on,
            "LLMSAFE_INPUT_PATH": str(target),
            "LLMSAFE_INPUT_SARIF": str(sarif),
            "PATH": f"{Path(sys.executable).parent}{os.pathsep}{environment['PATH']}",
            "PYTHONPATH": str(PROJECT_ROOT),
        }
    )
    return subprocess.run(
        ["bash", str(ACTION_RUNNER)],
        cwd=PROJECT_ROOT,
        env=environment,
        executable=None,
        check=False,
        capture_output=True,
        text=True,
    )


def test_action_safe_scan_writes_sarif_and_outputs() -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        source = root / "safe.py"
        sarif = root / "reports" / "llmsafe.sarif"
        output = root / "github-output.txt"
        source.write_text("print('safe')\n", encoding="utf-8")

        completed = run_action(source, sarif, output)
        assert sarif.exists(), completed.stderr
        payload = json.loads(sarif.read_text(encoding="utf-8"))
        action_outputs = output.read_text(encoding="utf-8").splitlines()

    assert completed.returncode == 0
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"] == []
    assert action_outputs == [f"sarif-file={sarif}", "exit-code=0"]


def test_action_preserves_policy_exit_code_after_writing_sarif() -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        source = root / "unsafe.py"
        sarif = root / "llmsafe.sarif"
        output = root / "github-output.txt"
        source.write_text("exec(code)\n", encoding="utf-8")

        completed = run_action(source, sarif, output)
        assert sarif.exists(), completed.stderr
        payload = json.loads(sarif.read_text(encoding="utf-8"))
        action_outputs = output.read_text(encoding="utf-8").splitlines()

    assert completed.returncode == 1
    assert payload["runs"][0]["results"][0]["ruleId"] == "PY002"
    assert action_outputs[-1] == "exit-code=1"


def test_action_forwards_config_and_baseline_inputs() -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        source = root / "reviewed.py"
        config = root / "llmsafe.toml"
        baseline = root / "baseline.json"
        source.write_text("eval(reviewed_expression)\n", encoding="utf-8")
        config.write_text(
            '[llmsafe]\ndisabled_rules = ["PY001"]\n',
            encoding="utf-8",
        )

        configured = run_action(
            source,
            root / "configured.sarif",
            root / "configured-output.txt",
            config=config,
        )
        assert main([str(source), "--write-baseline", str(baseline)]) == 0
        baselined = run_action(
            source,
            root / "baselined.sarif",
            root / "baselined-output.txt",
            baseline=baseline,
        )

    assert configured.returncode == 0
    assert baselined.returncode == 0


def test_action_reports_early_configuration_error_without_false_sarif_path() -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        source = root / "safe.py"
        config = root / "invalid.toml"
        sarif = root / "missing.sarif"
        output = root / "github-output.txt"
        source.write_text("print('safe')\n", encoding="utf-8")
        config.write_text("[llmsafe]\nfail_on = 'impossible'\n", encoding="utf-8")

        completed = run_action(source, sarif, output, config=config)
        action_outputs = output.read_text(encoding="utf-8").splitlines()

    assert completed.returncode == 2
    assert not sarif.exists()
    assert action_outputs == ["sarif-file=", "exit-code=2"]


def test_composite_action_declares_tested_contract() -> None:
    action = (PROJECT_ROOT / "action.yml").read_text(encoding="utf-8")
    workflow = (PROJECT_ROOT / ".github/workflows/code-scanning.yml").read_text(
        encoding="utf-8"
    )

    assert "scripts/run-action.sh" in action
    assert "value: ${{ steps.scan.outputs.sarif-file }}" in action
    assert "value: ${{ steps.scan.outputs.exit-code }}" in action
    assert "contents: read" in workflow
    assert "security-events: write" in workflow
    assert "pull_request_target" not in workflow
    assert "uses: ./" in (PROJECT_ROOT / ".github/workflows/ci.yml").read_text(
        encoding="utf-8"
    )
    assert sys.version_info >= (3, 9)
