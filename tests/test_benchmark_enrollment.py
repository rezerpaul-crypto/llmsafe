import copy
import json
from pathlib import Path

import pytest

from benchmarks.enrollment import EnrollmentError, main, validate_manifest

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def repository(identifier: str = "agent-alpha", family: str = "openai-agents"):
    return {
        "id": identifier,
        "repository_url": f"https://github.com/example/{identifier}",
        "commit": "a" * 40,
        "retrieved_at": "2026-09-22T12:00:00+00:00",
        "framework_family": family,
        "license": {
            "spdx": "Apache-2.0",
            "evidence_url": f"https://github.com/example/{identifier}/blob/{'a' * 40}/LICENSE",
        },
        "scope": {"include": ["src", "pyproject.toml"], "exclude": ["src/generated/**"]},
        "security_contact_ref": f"private:contacts/{identifier}",
        "consent": {
            "scan": {
                "granted": True,
                "recorded_at": "2026-09-22T11:30:00Z",
                "evidence_ref": f"private:consent/{identifier}",
            },
            "publish_identity": False,
            "publish_results": False,
            "publish_quote": False,
            "publish_logo": False,
            "publish_code_excerpt": False,
        },
        "active_incident_or_embargo": False,
    }


def manifest(*repositories):
    return {
        "schema_version": 1,
        "protocol_revision": "b" * 40,
        "repositories": list(repositories),
    }


def error_messages(document):
    with pytest.raises(EnrollmentError) as captured:
        validate_manifest(document)
    return captured.value.errors


def test_valid_manifest_returns_only_aggregate_permission_counts() -> None:
    first = repository()
    first["consent"]["publish_identity"] = True
    second = repository("agent-beta", "anthropic")
    second["commit"] = "c" * 40

    summary = validate_manifest(manifest(first, second)).to_dict()

    assert summary == {
        "schema_version": 1,
        "repositories": 2,
        "framework_family_count": 2,
        "framework_families": ["anthropic", "openai-agents"],
        "publication_permissions": {
            "publish_code_excerpt": 0,
            "publish_identity": 1,
            "publish_logo": 0,
            "publish_quote": 0,
            "publish_results": 0,
        },
        "ready_for_measurement": False,
    }
    rendered = json.dumps(summary)
    assert "github.com" not in rendered
    assert "private:" not in rendered


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda item: item["consent"]["scan"].update(granted=False), "must be true"),
        (lambda item: item.update(active_incident_or_embargo=True), "cannot be enrolled"),
        (lambda item: item.update(commit="main"), "object ID"),
        (lambda item: item["license"].update(spdx="NOASSERTION"), "scannable license"),
        (lambda item: item["scope"].update(include=["../secrets"]), "within the repository"),
        (lambda item: item["scope"].update(include=["src\\agent.py"]), "POSIX-style"),
        (lambda item: item["scope"].update(include=["src\nagent.py"]), "POSIX-style"),
        (lambda item: item.update(security_contact_ref="security@example.com"), "opaque private:"),
        (lambda item: item["consent"]["scan"].update(recorded_at="2026-09-22"), "UTC offset"),
        (lambda item: item["license"].update(evidence_url="http://example.test/LICENSE"), "HTTPS"),
        (lambda item: item.update(repository_url="https://[invalid"), "valid absolute HTTPS"),
    ],
)
def test_enrollment_stops_on_unsafe_or_ambiguous_inputs(mutate, expected) -> None:
    item = repository()
    mutate(item)

    assert any(expected in message for message in error_messages(manifest(item)))


def test_manifest_rejects_unknown_keys_and_duplicate_revisions() -> None:
    first = repository()
    first["consnet"] = {}
    second = copy.deepcopy(first)
    second["id"] = "agent-beta"
    second.pop("consnet")

    errors = error_messages(manifest(first, second))

    assert any("unknown keys: consnet" in message for message in errors)
    assert "repository URL and commit pairs must be unique" in errors


def test_ready_corpus_requires_three_distinct_framework_families() -> None:
    entries = [
        repository("agent-alpha", "openai-agents"),
        repository("agent-beta", "anthropic"),
        repository("agent-gamma", "mcp"),
    ]
    for index, item in enumerate(entries):
        item["commit"] = str(index + 1) * 40

    assert validate_manifest(manifest(*entries)).ready_for_measurement is True


def test_cli_reports_validation_errors_without_echoing_private_register(
    tmp_path: Path, capsys
) -> None:
    item = repository()
    item["consent"]["scan"]["granted"] = False
    path = tmp_path / "private-enrollment.json"
    path.write_text(json.dumps(manifest(item)), encoding="utf-8")

    assert main([str(path)]) == 2

    captured = capsys.readouterr()
    assert "consent.scan.granted must be true" in captured.err
    assert "github.com" not in captured.out + captured.err
    assert "private:contacts" not in captured.out + captured.err


def test_cli_can_require_a_measurement_ready_corpus(tmp_path: Path, capsys) -> None:
    path = tmp_path / "private-enrollment.json"
    path.write_text(json.dumps(manifest(repository())), encoding="utf-8")

    assert main([str(path), "--require-ready-corpus"]) == 1

    captured = capsys.readouterr()
    assert '"ready_for_measurement": false' in captured.out
    assert "at least 3 framework families" in captured.err


def test_public_template_is_fail_closed_and_forbids_committing_the_register() -> None:
    guide = (PROJECT_ROOT / "docs" / "benchmark-enrollment.md").read_text(encoding="utf-8")

    assert '"granted": false' in guide
    assert "keep it outside the LLMSafe checkout" in guide
    assert "A license alone is not benchmark consent." in guide
    assert "Successful validation does not" in guide
