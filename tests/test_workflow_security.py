import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOT = PROJECT_ROOT / ".github" / "workflows"
RELEASE_INPUT = PROJECT_ROOT / "requirements" / "release.in"
RELEASE_LOCK = PROJECT_ROOT / "requirements" / "release-linux-py312.txt"


def workflow_text() -> str:
    return "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(WORKFLOW_ROOT.glob("*.yml"))
    )


def test_external_actions_are_pinned_to_full_commit_shas() -> None:
    uses = re.findall(r"^\s*-?\s*uses:\s*([^\s#]+)", workflow_text(), flags=re.MULTILINE)
    external = [value for value in uses if not value.startswith("./")]

    assert external
    assert all(re.search(r"@[0-9a-f]{40}$", value) for value in external)


def test_artifact_actions_use_node24_release_lines() -> None:
    artifact_actions = re.findall(
        r"actions/(upload|download)-artifact@[0-9a-f]{40}\s+#\s+v(\d+)",
        workflow_text(),
    )

    assert {action for action, _ in artifact_actions} == {"upload", "download"}
    assert all(
        int(major) >= {"upload": 6, "download": 7}[action]
        for action, major in artifact_actions
    )


def test_linux_runner_image_is_explicitly_pinned() -> None:
    workflows = workflow_text()
    linux_runners = re.findall(r"^\s*runs-on:\s*(ubuntu-[^\s#]+)", workflows, flags=re.MULTILINE)

    assert linux_runners
    assert set(linux_runners) == {"ubuntu-24.04"}
    assert "ubuntu-latest" not in workflows


def test_release_toolchain_is_exactly_pinned_and_hash_checked() -> None:
    direct_lines = {
        line
        for line in RELEASE_INPUT.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    }
    direct_pins = {
        requirement.split("==", maxsplit=1)[0]: requirement.split("==", maxsplit=1)[1]
        for requirement in direct_lines
    }
    lock = RELEASE_LOCK.read_text(encoding="utf-8")
    package_starts = list(
        re.finditer(
            r"^(?P<name>[a-z0-9][a-z0-9._-]*)==(?P<version>[^\\\s]+) \\$",
            lock,
            flags=re.MULTILINE,
        )
    )

    assert set(direct_pins) == {"build", "setuptools", "twine", "wheel"}
    assert "--only-binary :all:" in lock
    assert package_starts
    assert len(package_starts) == len({match["name"] for match in package_starts})
    for index, match in enumerate(package_starts):
        block_end = (
            package_starts[index + 1].start()
            if index + 1 < len(package_starts)
            else len(lock)
        )
        assert "--hash=sha256:" in lock[match.start() : block_end]
    for package, version in direct_pins.items():
        line_ending = "\\"
        assert f"{package}=={version} {line_ending}" in lock
    pyproject = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert f'requires = ["setuptools=={direct_pins["setuptools"]}"]' in pyproject

    for workflow_name in ("ci.yml", "release.yml"):
        workflow = (WORKFLOW_ROOT / workflow_name).read_text(encoding="utf-8")
        assert "pip install --disable-pip-version-check --require-hashes" in workflow
        assert "-r requirements/release-linux-py312.txt" in workflow
        assert "python -m build --no-isolation" in workflow
        assert "pip install --upgrade build twine" not in workflow


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


def test_dependabot_preserves_oldest_supported_python() -> None:
    dependabot = (PROJECT_ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    pyproject = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert 'requires-python = ">=3.9"' in pyproject
    assert "dependency-name: pytest" in dependabot
    assert "dependency-name: setuptools" in dependabot
    assert dependabot.count('update-types: ["version-update:semver-major"]') == 2
