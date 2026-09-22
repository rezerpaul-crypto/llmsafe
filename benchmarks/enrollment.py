"""Validate consent-gated enrollment for the real-world benchmark.

The private enrollment register is intentionally kept outside this repository. This module validates
that register without cloning or scanning any third-party source code and emits only aggregate data.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Mapping, Sequence, Tuple
from urllib.parse import urlsplit

SCHEMA_VERSION = 1
MAX_REPOSITORIES = 10
REQUIRED_FAMILIES = 3
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
PRIVATE_REFERENCE_PATTERN = re.compile(r"private:[a-z0-9][a-z0-9._/-]*\Z")
IDENTIFIER_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]*\Z")

TOP_LEVEL_KEYS = {"schema_version", "protocol_revision", "repositories"}
REPOSITORY_KEYS = {
    "id",
    "repository_url",
    "commit",
    "retrieved_at",
    "framework_family",
    "license",
    "scope",
    "security_contact_ref",
    "consent",
    "active_incident_or_embargo",
}
LICENSE_KEYS = {"spdx", "evidence_url"}
SCOPE_KEYS = {"include", "exclude"}
CONSENT_KEYS = {
    "scan",
    "publish_identity",
    "publish_results",
    "publish_quote",
    "publish_logo",
    "publish_code_excerpt",
}
SCAN_CONSENT_KEYS = {"granted", "recorded_at", "evidence_ref"}
PUBLICATION_PERMISSIONS = tuple(sorted(CONSENT_KEYS - {"scan"}))


class EnrollmentError(ValueError):
    """Raised when the private enrollment register is unsafe or incomplete."""

    def __init__(self, errors: Sequence[str]):
        self.errors = tuple(errors)
        super().__init__("; ".join(self.errors))


@dataclass(frozen=True)
class EnrollmentSummary:
    """Privacy-safe aggregate facts about an enrollment register."""

    repositories: int
    framework_families: Tuple[str, ...]
    publication_permissions: Mapping[str, int]

    @property
    def ready_for_measurement(self) -> bool:
        return (
            self.repositories > 0
            and self.repositories <= MAX_REPOSITORIES
            and len(self.framework_families) >= REQUIRED_FAMILIES
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "repositories": self.repositories,
            "framework_family_count": len(self.framework_families),
            "framework_families": list(self.framework_families),
            "publication_permissions": dict(self.publication_permissions),
            "ready_for_measurement": self.ready_for_measurement,
        }


def _expect_mapping(value: Any, location: str, errors: List[str]) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    errors.append(f"{location} must be an object")
    return {}


def _expect_exact_keys(
    value: Mapping[str, Any], expected: set[str], location: str, errors: List[str]
) -> None:
    missing = sorted(expected - set(value))
    unknown = sorted(set(value) - expected)
    if missing:
        errors.append(f"{location} is missing keys: {', '.join(missing)}")
    if unknown:
        errors.append(f"{location} has unknown keys: {', '.join(unknown)}")


def _expect_nonempty_string(value: Any, location: str, errors: List[str]) -> str:
    if isinstance(value, str) and value.strip() == value and value:
        return value
    errors.append(f"{location} must be a non-empty, trimmed string")
    return ""


def _validate_https_url(value: Any, location: str, errors: List[str]) -> None:
    url = _expect_nonempty_string(value, location, errors)
    if not url:
        return
    try:
        parsed = urlsplit(url)
    except ValueError:
        errors.append(f"{location} must be a valid absolute HTTPS URL")
        return
    if parsed.scheme != "https" or not parsed.hostname:
        errors.append(f"{location} must be an absolute HTTPS URL")
    if parsed.username is not None or parsed.password is not None:
        errors.append(f"{location} must not contain credentials")
    if parsed.query or parsed.fragment:
        errors.append(f"{location} must not contain a query or fragment")


def _validate_timestamp(value: Any, location: str, errors: List[str]) -> None:
    timestamp = _expect_nonempty_string(value, location, errors)
    if not timestamp:
        return
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"{location} must be an ISO 8601 timestamp")
        return
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        errors.append(f"{location} must include a UTC offset")


def _validate_private_reference(value: Any, location: str, errors: List[str]) -> None:
    reference = _expect_nonempty_string(value, location, errors)
    if reference and not PRIVATE_REFERENCE_PATTERN.fullmatch(reference):
        errors.append(f"{location} must be an opaque private: reference, not contact data")


def _validate_scope_paths(value: Any, location: str, errors: List[str], *, required: bool) -> None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        errors.append(f"{location} must be a list of POSIX-style relative paths")
        return
    if required and not value:
        errors.append(f"{location} must contain at least one path")
    if len(set(value)) != len(value):
        errors.append(f"{location} must not contain duplicate paths")
    for index, candidate in enumerate(value):
        item_location = f"{location}[{index}]"
        has_control_character = any(ord(character) < 32 for character in candidate)
        if not candidate or "\\" in candidate or has_control_character:
            errors.append(f"{item_location} must be a POSIX-style relative path")
            continue
        path = PurePosixPath(candidate)
        if path.is_absolute() or ".." in path.parts:
            errors.append(f"{item_location} must stay within the repository")
        if candidate != "." and path.as_posix() != candidate:
            errors.append(f"{item_location} must be normalized")


def _validate_boolean(value: Any, location: str, errors: List[str]) -> bool:
    if type(value) is bool:
        return value
    errors.append(f"{location} must be true or false")
    return False


def _validate_repository(entry: Any, index: int, errors: List[str]) -> Dict[str, Any]:
    location = f"repositories[{index}]"
    repository = _expect_mapping(entry, location, errors)
    _expect_exact_keys(repository, REPOSITORY_KEYS, location, errors)

    identifier = _expect_nonempty_string(repository.get("id"), f"{location}.id", errors)
    if identifier and not IDENTIFIER_PATTERN.fullmatch(identifier):
        errors.append(
            f"{location}.id must use lowercase letters, digits, dots, dashes, or underscores"
        )

    _validate_https_url(repository.get("repository_url"), f"{location}.repository_url", errors)
    commit = _expect_nonempty_string(repository.get("commit"), f"{location}.commit", errors)
    if commit and not COMMIT_PATTERN.fullmatch(commit):
        errors.append(f"{location}.commit must be a lowercase 40- or 64-character hex object ID")
    _validate_timestamp(repository.get("retrieved_at"), f"{location}.retrieved_at", errors)

    family = _expect_nonempty_string(
        repository.get("framework_family"), f"{location}.framework_family", errors
    )
    if family and not IDENTIFIER_PATTERN.fullmatch(family):
        errors.append(f"{location}.framework_family must be a stable lowercase identifier")

    license_data = _expect_mapping(repository.get("license"), f"{location}.license", errors)
    _expect_exact_keys(license_data, LICENSE_KEYS, f"{location}.license", errors)
    spdx = _expect_nonempty_string(license_data.get("spdx"), f"{location}.license.spdx", errors)
    if spdx.upper() in {"NONE", "NOASSERTION"}:
        errors.append(f"{location}.license.spdx must identify a scannable license")
    _validate_https_url(
        license_data.get("evidence_url"), f"{location}.license.evidence_url", errors
    )

    scope = _expect_mapping(repository.get("scope"), f"{location}.scope", errors)
    _expect_exact_keys(scope, SCOPE_KEYS, f"{location}.scope", errors)
    _validate_scope_paths(scope.get("include"), f"{location}.scope.include", errors, required=True)
    _validate_scope_paths(scope.get("exclude"), f"{location}.scope.exclude", errors, required=False)

    _validate_private_reference(
        repository.get("security_contact_ref"), f"{location}.security_contact_ref", errors
    )

    consent = _expect_mapping(repository.get("consent"), f"{location}.consent", errors)
    _expect_exact_keys(consent, CONSENT_KEYS, f"{location}.consent", errors)
    scan = _expect_mapping(consent.get("scan"), f"{location}.consent.scan", errors)
    _expect_exact_keys(scan, SCAN_CONSENT_KEYS, f"{location}.consent.scan", errors)
    if not _validate_boolean(scan.get("granted"), f"{location}.consent.scan.granted", errors):
        errors.append(f"{location}.consent.scan.granted must be true before enrollment")
    _validate_timestamp(scan.get("recorded_at"), f"{location}.consent.scan.recorded_at", errors)
    _validate_private_reference(
        scan.get("evidence_ref"), f"{location}.consent.scan.evidence_ref", errors
    )
    publication = {
        permission: _validate_boolean(
            consent.get(permission), f"{location}.consent.{permission}", errors
        )
        for permission in PUBLICATION_PERMISSIONS
    }

    if _validate_boolean(
        repository.get("active_incident_or_embargo"),
        f"{location}.active_incident_or_embargo",
        errors,
    ):
        errors.append(f"{location} cannot be enrolled during an incident or embargo")

    return {
        "id": identifier,
        "repository_url": repository.get("repository_url"),
        "commit": commit,
        "family": family,
        "publication": publication,
    }


def validate_manifest(document: Any) -> EnrollmentSummary:
    """Validate a private enrollment register and return privacy-safe aggregate facts."""

    errors: List[str] = []
    manifest = _expect_mapping(document, "manifest", errors)
    _expect_exact_keys(manifest, TOP_LEVEL_KEYS, "manifest", errors)

    version = manifest.get("schema_version")
    if type(version) is not int or version != SCHEMA_VERSION:
        errors.append(f"manifest.schema_version must equal {SCHEMA_VERSION}")

    revision = _expect_nonempty_string(
        manifest.get("protocol_revision"), "manifest.protocol_revision", errors
    )
    if revision and not COMMIT_PATTERN.fullmatch(revision):
        errors.append(
            "manifest.protocol_revision must be a lowercase 40- or 64-character object ID"
        )

    raw_repositories = manifest.get("repositories")
    if not isinstance(raw_repositories, list):
        errors.append("manifest.repositories must be a list")
        raw_repositories = []
    if not raw_repositories:
        errors.append("manifest.repositories must contain at least one enrollment")
    if len(raw_repositories) > MAX_REPOSITORIES:
        errors.append(f"manifest.repositories must contain at most {MAX_REPOSITORIES} enrollments")

    repositories = [
        _validate_repository(repository, index, errors)
        for index, repository in enumerate(raw_repositories)
    ]
    identifiers = [repository["id"] for repository in repositories if repository["id"]]
    if len(set(identifiers)) != len(identifiers):
        errors.append("repository ids must be unique")
    revisions = [
        (repository["repository_url"], repository["commit"])
        for repository in repositories
        if repository["repository_url"] and repository["commit"]
    ]
    if len(set(revisions)) != len(revisions):
        errors.append("repository URL and commit pairs must be unique")

    if errors:
        raise EnrollmentError(errors)

    permissions = {
        permission: sum(repository["publication"][permission] for repository in repositories)
        for permission in PUBLICATION_PERMISSIONS
    }
    families = tuple(sorted({repository["family"] for repository in repositories}))
    return EnrollmentSummary(
        repositories=len(repositories),
        framework_families=families,
        publication_permissions=permissions,
    )


def load_manifest(path: Path) -> EnrollmentSummary:
    """Load and validate a UTF-8 JSON enrollment register."""

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EnrollmentError((f"could not read enrollment manifest: {error}",)) from error
    return validate_manifest(document)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate consent and scope before any real-world benchmark scan.",
    )
    parser.add_argument("manifest", type=Path, help="private enrollment manifest JSON")
    parser.add_argument(
        "--require-ready-corpus",
        action="store_true",
        help=(
            "fail unless the consented corpus covers at least "
            f"{REQUIRED_FAMILIES} framework families"
        ),
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        summary = load_manifest(args.manifest)
    except EnrollmentError as error:
        for message in error.errors:
            print(f"error: {message}", file=sys.stderr)
        return 2

    print(json.dumps(summary.to_dict(), indent=2, sort_keys=True))
    if args.require_ready_corpus and not summary.ready_for_measurement:
        print(
            f"error: consented corpus must cover at least {REQUIRED_FAMILIES} framework families",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
