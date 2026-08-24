import importlib.util
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_PATH = PROJECT_ROOT / "examples/rules/debug_agent.py"
SPEC = importlib.util.spec_from_file_location("debug_agent_example", EXAMPLE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
DebugAgentRule = MODULE.DebugAgentRule


def findings_for(content: str, filename: str = "agent.py"):
    return list(DebugAgentRule().scan(Path(filename), content))


def test_example_rule_detects_literal_debug_mode() -> None:
    findings = findings_for("from framework import Agent\nagent = Agent(debug=True)\n")

    assert len(findings) == 1
    assert findings[0].rule_id == "EXAMPLE001"
    assert findings[0].line == 2
    assert findings[0].column == 9
    assert "debug=True" in findings[0].message
    assert findings[0].remediation


def test_example_rule_allows_debug_mode_to_be_disabled() -> None:
    assert findings_for("agent = Agent(debug=False)\n") == []


def test_example_rule_avoids_ambiguous_and_unrelated_edge_cases() -> None:
    content = """
debug_setting = load_environment_setting()
agent = Agent(debug=debug_setting)
client = HttpClient(debug=True)
text = "Agent(debug=True)"
"""

    assert findings_for(content) == []
    assert findings_for("Agent(debug=True)\n", filename="notes.txt") == []
    assert findings_for("Agent(debug=True\n") == []
