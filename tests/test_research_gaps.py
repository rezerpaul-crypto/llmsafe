"""Safety and signal-isolation checks for the opt-in research harness."""

import json
import runpy
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HARNESS = runpy.run_path(str(ROOT / "scripts/research_gaps.py"))


def test_research_never_executes_fixture_source() -> None:
    data = {
        "cases": [
            {
                "id": "execution-canary",
                "focus": "FLOW001",
                "expected": True,
                "files": {
                    "agent.py": (
                        'raise RuntimeError("Fixture source was executed")\n'
                        "def handle(user_input):\n"
                        "    return eval(user_input)\n"
                    )
                },
            }
        ]
    }
    result = HARNESS["run_cases"](data)
    assert result["cases"][0]["passed"] is True
    assert result["cases"][0]["errors"] == 0


def test_generic_findings_cannot_satisfy_a_different_focus_signal() -> None:
    data = {
        "cases": [
            {
                "id": "different-signal",
                "focus": "FLOW002",
                "expected": True,
                "files": {"agent.py": "def handle(user_input):\n    return eval(user_input)\n"},
            }
        ]
    }
    row = HARNESS["run_cases"](data)["cases"][0]
    assert "PY001" in row["all_rule_ids"]
    assert "FLOW001" in row["all_rule_ids"]
    assert row["passed"] is False


@pytest.mark.parametrize("unsafe", ("../escape.py", "/outside.py", "C:\\outside.py", "a/../b.py"))
def test_research_rejects_fixture_path_escape(tmp_path: Path, unsafe: str) -> None:
    fixture = tmp_path / "cases.json"
    fixture.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "cases": [
                    {
                        "id": "escape",
                        "focus": "FLOW001",
                        "expected": True,
                        "files": {unsafe: "pass\n"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="inside"):
        HARNESS["load_cases"](fixture)
