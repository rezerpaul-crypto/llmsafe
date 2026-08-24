import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOT = PROJECT_ROOT / ".github" / "workflows"


def workflow_text() -> str:
    return "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(WORKFLOW_ROOT.glob("*.yml"))
    )


def test_external_actions_are_pinned_to_full_commit_shas() -> None:
    uses = re.findall(r"^\s*-?\s*uses:\s*([^\s#]+)", workflow_text(), flags=re.MULTILINE)
    external = [value for value in uses if not value.startswith("./")]

    assert external
    assert all(re.search(r"@[0-9a-f]{40}$", value) for value in external)


def test_checkout_never_persists_workflow_credentials() -> None:
    workflows = workflow_text()

    assert workflows.count("actions/checkout@") == workflows.count("persist-credentials: false")


def test_privileged_permissions_are_narrowly_scoped() -> None:
    code_scanning = (WORKFLOW_ROOT / "code-scanning.yml").read_text(encoding="utf-8")
    release = (WORKFLOW_ROOT / "release.yml").read_text(encoding="utf-8")

    scan_job, upload_job = code_scanning.split("\n  upload:\n", maxsplit=1)
    assert "security-events: write" not in scan_job
    assert "security-events: write" in upload_job
    assert "needs.scan.outputs.sarif-file != ''" in upload_job
    assert "pull_request_target" not in code_scanning
    assert "environment:\n      name: pypi" in release
    assert "id-token: write" in release
    assert "contents: write" not in workflow_text()


def test_dependabot_covers_python_and_workflow_dependencies() -> None:
    dependabot = (PROJECT_ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")

    assert "package-ecosystem: pip" in dependabot
    assert "package-ecosystem: github-actions" in dependabot
