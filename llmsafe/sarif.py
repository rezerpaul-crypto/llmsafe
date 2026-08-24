"""SARIF 2.1.0 rendering for GitHub code scanning and other consumers."""

from pathlib import Path
from typing import Any, Dict, Iterable, List

from llmsafe import __version__
from llmsafe.baseline import finding_fingerprint
from llmsafe.catalog import RULES_BY_ID
from llmsafe.models import Finding, ScanResult, Severity

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SEVERITY_LEVEL = {
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}
SECURITY_SEVERITY = {
    Severity.LOW: "2.0",
    Severity.MEDIUM: "5.0",
    Severity.HIGH: "8.0",
    Severity.CRITICAL: "9.5",
}


def to_sarif(result: ScanResult) -> Dict[str, Any]:
    """Convert a scan result to a deterministic SARIF document."""

    findings = list(result.findings)
    rules = _rules(findings)
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "LLMSafe",
                        "version": __version__,
                        "informationUri": "https://github.com/rezerpaul-crypto/llmsafe",
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": "llmsafe/"},
                "results": [_result(finding) for finding in findings],
                "invocations": [
                    {
                        "executionSuccessful": not result.errors,
                        "properties": {
                            "scannedFiles": result.scanned_files,
                            "skippedFiles": result.skipped_files,
                            "baselineFindings": result.baseline_findings,
                            "scanErrors": len(result.errors),
                        },
                    }
                ],
            }
        ],
    }


def _rules(findings: Iterable[Finding]) -> List[Dict[str, Any]]:
    by_id: Dict[str, Finding] = {}
    for finding in findings:
        by_id.setdefault(finding.rule_id, finding)
    rules = []
    for _, finding in sorted(by_id.items()):
        metadata = RULES_BY_ID.get(finding.rule_id)
        title = metadata.title if metadata else finding.title
        description = metadata.description if metadata else finding.message
        remediation = metadata.remediation if metadata else finding.remediation
        severity = metadata.severity if metadata else finding.severity
        tags = ["security", "ai", "agentic-applications"]
        if metadata:
            tags.append(metadata.family)
        rules.append(
            {
                "id": finding.rule_id,
                "name": _rule_name(title),
                "shortDescription": {"text": title},
                "fullDescription": {"text": description},
                "help": {"text": remediation},
                "defaultConfiguration": {"level": SEVERITY_LEVEL[severity]},
                "properties": {
                    "tags": tags,
                    "security-severity": SECURITY_SEVERITY[severity],
                    "severity": severity.value,
                },
            }
        )
    return rules


def _result(finding: Finding) -> Dict[str, Any]:
    location: Dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": _uri(finding.path)},
            "region": {"startLine": finding.line, "startColumn": finding.column},
        }
    }
    related = [
        {
            "id": index,
            "message": {"text": evidence.message},
            "physicalLocation": {
                "artifactLocation": {"uri": _uri(evidence.path or finding.path)},
                "region": {"startLine": evidence.line, "startColumn": evidence.column},
            },
        }
        for index, evidence in enumerate(finding.evidence, start=1)
    ]
    rendered: Dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": SEVERITY_LEVEL[finding.severity],
        "message": {"text": f"{finding.message} Fix: {finding.remediation}"},
        "locations": [location],
        "partialFingerprints": {"primaryLocationLineHash": finding_fingerprint(finding)},
        "properties": {"severity": finding.severity.value},
    }
    if related:
        rendered["relatedLocations"] = related
    return rendered


def _uri(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _rule_name(title: str) -> str:
    return "".join(character for character in title.title() if character.isalnum())
