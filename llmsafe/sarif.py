"""SARIF 2.1.0 rendering for GitHub code scanning and other consumers."""

import hashlib
from pathlib import Path
from typing import Any, Dict, Iterable, List

from llmsafe import __version__
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
    return [
        {
            "id": finding.rule_id,
            "name": _rule_name(finding.title),
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.message},
            "help": {"text": finding.remediation},
            "defaultConfiguration": {"level": SEVERITY_LEVEL[finding.severity]},
            "properties": {
                "tags": ["security", "ai", "agentic-applications"],
                "security-severity": SECURITY_SEVERITY[finding.severity],
                "severity": finding.severity.value,
            },
        }
        for _, finding in sorted(by_id.items())
    ]


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
                "artifactLocation": {"uri": _uri(finding.path)},
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
        "partialFingerprints": {"primaryLocationLineHash": _fingerprint(finding)},
        "properties": {"severity": finding.severity.value},
    }
    if related:
        rendered["relatedLocations"] = related
    return rendered


def _fingerprint(finding: Finding) -> str:
    identity = "\0".join(
        (
            finding.rule_id,
            _uri(finding.path),
            finding.title,
            finding.message.split(" Source:", 1)[0],
        )
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _uri(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _rule_name(title: str) -> str:
    return "".join(character for character in title.title() if character.isalnum())
