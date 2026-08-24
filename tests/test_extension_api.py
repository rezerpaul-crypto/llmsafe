import tempfile
from pathlib import Path
from typing import Iterable

from llmsafe.api import Finding, Rule, Severity, built_in_rules, scan_paths


class OrganizationBoundaryRule:
    def scan(self, path: Path, content: str) -> Iterable[Finding]:
        if "send_to_internal_admin(" not in content:
            return
        yield Finding(
            rule_id="ORG001",
            title="Organization admin boundary",
            severity=Severity.HIGH,
            path=path,
            line=1,
            column=1,
            message="A project-specific admin operation requires review.",
            remediation="Require the organization's authorization policy before this operation.",
        )


def accepts_rule(rule: Rule) -> Rule:
    return rule


def test_public_api_runs_builtins_and_explicit_custom_rule() -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        source = Path(temporary_directory) / "agent.py"
        source.write_text(
            "send_to_internal_admin(request_payload)\nexec(code)\n",
            encoding="utf-8",
        )

        result = scan_paths([source], extra_rules=[accepts_rule(OrganizationBoundaryRule())])

    assert {finding.rule_id for finding in result.findings} == {"ORG001", "PY002"}
    assert result.errors == ()


def test_public_api_applies_policy_to_custom_rule_ids() -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        source = Path(temporary_directory) / "agent.py"
        source.write_text("send_to_internal_admin(payload)\n", encoding="utf-8")

        result = scan_paths(
            [source],
            extra_rules=[OrganizationBoundaryRule()],
            disabled_rules=["org001"],
        )

    assert result.findings == ()


def test_built_in_rule_order_is_stable_and_returned_as_tuple() -> None:
    first = built_in_rules()
    second = built_in_rules()

    assert isinstance(first, tuple)
    assert [type(rule).__name__ for rule in first] == [
        type(rule).__name__ for rule in second
    ]
    assert len(first) == 7
