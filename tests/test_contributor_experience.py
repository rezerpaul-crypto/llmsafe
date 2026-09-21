from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
GUIDE = PROJECT_ROOT / "docs" / "contributor-sprint.md"


def test_contributor_sprint_has_a_safe_first_contribution_path() -> None:
    guide = GUIDE.read_text(encoding="utf-8")

    assert "good first issue" in guide
    assert "python3 scripts/dev.py" in guide
    assert "python3 scripts/dev.py --check-only" in guide
    assert "vulnerable, safe, and adversarial" in guide
    assert "Read the complete issue and its comments" in guide
    assert "check for a linked or competing pull request" in guide
    assert "design gate" in guide
    assert "not ownership of a task" in guide


def test_contributor_review_contract_does_not_overpromise_or_weaken_safety() -> None:
    guide = GUIDE.read_text(encoding="utf-8")

    assert "first substantive maintainer response within\n  24 hours" in guide
    assert "not a service-level agreement" in guide
    assert "Awaiting approval" in guide
    assert "exact pull-request head SHA" in guide
    assert "A new commit invalidates earlier test evidence" in guide
    assert "Passing CI is required but is not automatic approval" in guide
    assert "full action SHA pins" in guide
    assert "no persisted checkout credentials" in guide
    assert "Never lower the coverage threshold" in guide
    assert "Claude" not in guide


def test_contributor_sprint_is_reachable_from_public_entry_points() -> None:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    contributing = (PROJECT_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    issue_config = (
        PROJECT_ROOT / ".github" / "ISSUE_TEMPLATE" / "config.yml"
    ).read_text(encoding="utf-8")

    assert GUIDE.is_file()
    assert "docs/contributor-sprint.md" in readme
    assert "docs/contributor-sprint.md" in contributing
    assert "docs/contributor-sprint.md" in issue_config
