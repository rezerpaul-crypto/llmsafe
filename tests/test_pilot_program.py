from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_pilot_program_has_bounded_scope_and_reproduction_path() -> None:
    program = (PROJECT_ROOT / "docs" / "pilot-program.md").read_text(encoding="utf-8")

    assert "v0.3.0rc1" in program
    assert "one public repository at one immutable commit" in program
    assert 'pip install --pre "llmsafe==0.3.0rc1"' in program
    assert "not a penetration test" in program
    assert "separate explicit approval" in program
    assert "private source code during this initial" in program


def test_pilot_issue_form_does_not_request_sensitive_material() -> None:
    form = (
        PROJECT_ROOT / ".github" / "ISSUE_TEMPLATE" / "pilot_request.yml"
    ).read_text(encoding="utf-8")

    assert "Public repository URL" in form
    assert "Proposed commit or tag" in form
    assert "Published private security-contact instructions" in form
    assert "no sensitive material" in form
    assert "scan scope and any public disclosure require separate explicit agreement" in form
    assert "private source code" in form
