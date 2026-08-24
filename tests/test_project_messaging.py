import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MARKDOWN_LINK = re.compile(r"\[[^]]+\]\(([^)]+)\)")


def test_readme_has_a_fast_evidence_based_entry_path() -> None:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")

    required = (
        "Static security analysis built for Python AI agents.",
        "No API key. No model calls. No source upload.",
        "## Start in 60 seconds",
        "## See the risk, not just the API",
        "docs/why-llmsafe.md",
        "docs/github-action.md",
        "docs/pilot-program.md",
        "does not certify that an AI system is secure",
    )

    for text in required:
        assert text in readme


def test_positioning_states_scope_and_complementary_layers() -> None:
    positioning = (PROJECT_ROOT / "docs" / "why-llmsafe.md").read_text(encoding="utf-8")

    assert "Can untrusted AI data reach a dangerous capability?" in positioning
    assert "## What LLMSafe is not" in positioning
    assert "Model evaluation / red-team tooling" in positioning
    assert "SCA / dependency scanning" in positioning
    assert "Runtime guardrails, sandbox, and authorization" in positioning
    assert "not unverified\nclaims or vanity metrics" in positioning


def test_public_roadmap_matches_the_release_gate() -> None:
    roadmap = (PROJECT_ROOT / "ROADMAP.md").read_text(encoding="utf-8")

    assert "### v0.3.0rc1" in roadmap
    assert "at least three public Python AI, agent, or MCP projects" in roadmap
    assert "at least one externally reproduced scan" in roadmap
    assert "Publish stable `v0.3.0` only" in roadmap


@pytest.mark.parametrize("relative_path", ("README.md", "ROADMAP.md", "docs/why-llmsafe.md"))
def test_positioning_documents_have_no_broken_local_links(relative_path: str) -> None:
    source = PROJECT_ROOT / relative_path
    contents = source.read_text(encoding="utf-8")

    for destination in MARKDOWN_LINK.findall(contents):
        target = destination.split("#", 1)[0]
        if not target or "://" in target:
            continue
        assert (source.parent / target).resolve().exists(), (
            f"{relative_path} links to missing local target {destination}"
        )
