import re
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_development_script_help_is_available() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/dev.py", "--help"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "--check-only" in result.stdout
    assert "--current" in result.stdout


def test_ci_matrix_covers_every_declared_python_version() -> None:
    pyproject = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    workflow = (PROJECT_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    declared = set(re.findall(r'"Programming Language :: Python :: (\d+\.\d+)"', pyproject))
    matrix_match = re.search(r"python-version:\s*\[([^]]+)]", workflow)

    assert matrix_match is not None
    matrix = set(re.findall(r'"(\d+\.\d+)"', matrix_match.group(1)))
    assert matrix == declared
    assert "python scripts/dev.py --current" in workflow
