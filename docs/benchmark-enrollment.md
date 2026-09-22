# Real-world benchmark enrollment

LLMSafe does not scan a third-party project for the real-world benchmark until that project's
private enrollment record passes the offline gate. The enrollment record is operational research
data: keep it outside the LLMSafe checkout and do not commit it, paste it into an issue, or attach it
to a workflow run.

## Private register format

The register has a version, the immutable LLMSafe revision containing the reviewed protocol, and
one to ten repository entries:

```json
{
  "schema_version": 1,
  "protocol_revision": "<40-or-64-character-lowercase-object-id>",
  "repositories": [
    {
      "id": "internal-project-id",
      "repository_url": "https://example.org/owner/project",
      "commit": "<40-or-64-character-lowercase-object-id>",
      "retrieved_at": "2026-09-22T12:00:00Z",
      "framework_family": "mcp",
      "license": {
        "spdx": "Apache-2.0",
        "evidence_url": "https://example.org/owner/project/blob/<commit>/LICENSE"
      },
      "scope": {
        "include": ["src", "pyproject.toml"],
        "exclude": ["src/generated/**"]
      },
      "security_contact_ref": "private:contacts/internal-project-id",
      "consent": {
        "scan": {
          "granted": false,
          "recorded_at": "2026-09-22T11:30:00Z",
          "evidence_ref": "private:consent/internal-project-id"
        },
        "publish_identity": false,
        "publish_results": false,
        "publish_quote": false,
        "publish_logo": false,
        "publish_code_excerpt": false
      },
      "active_incident_or_embargo": false
    }
  ]
}
```

The template intentionally has `scan.granted` set to `false` and therefore cannot pass. Set it to
`true` only after a maintainer explicitly opts in and the private evidence reference points to that
record. A license alone is not benchmark consent.

Opaque `private:` values are references into the maintainer's protected evidence store. They must
not contain an email address, message body, access token, or other contact data. Publication flags
are independent: consent to scan does not grant permission to identify a project, publish results,
quote a maintainer, use a logo, or reproduce code.

Scope paths are repository-relative POSIX paths. Absolute paths, parent traversal, backslashes,
control characters, duplicate paths, floating branches, mutable tags, URLs with credentials, and
unknown fields are rejected.

## Validation

Validate records incrementally while forming the corpus:

```console
python -m benchmarks.enrollment /private/path/enrollment.json
```

Before any measurement, require the complete selection gate:

```console
python -m benchmarks.enrollment /private/path/enrollment.json --require-ready-corpus
```

Exit code `0` means the register is structurally safe and, with `--require-ready-corpus`, covers at
least three framework families. Exit code `1` means valid individual enrollments do not yet form a
measurement-ready corpus. Exit code `2` means the register is malformed or an enrollment is unsafe.

The command performs no network access. Successful validation does not fetch source, run LLMSafe,
or authorize publication. Continue with the frozen environment, ground-truth, disclosure, and stop
conditions in the [benchmark protocol](real-world-benchmark-protocol.md).
