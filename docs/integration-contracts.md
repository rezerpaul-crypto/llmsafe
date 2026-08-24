# Integration contracts

LLMSafe exposes four machine-facing contracts: scan JSON, SARIF 2.1.0, rule-catalog JSON, and process
exit codes. This page defines what integrations may rely on for the `0.3.x` line.

## Scan JSON v1

`llmsafe PATH --format json` returns a document with `schema_version: 1`, the LLMSafe package
`version`, a `summary`, ordered `findings`, and ordered scan `errors`.

The normative field shape is [scan-v1.schema.json](schemas/scan-v1.schema.json). Important guarantees:

- findings are sorted by severity, path, line, and rule ID;
- every finding has a stable rule ID, severity, location, remediation, and evidence array;
- cross-file evidence may include its own `path`; same-file evidence omits it;
- counts are non-negative and agree with the rendered arrays;
- keys are serialized deterministically.

Changing, removing, or retyping a v1 field requires a new schema version. The package version is not
the schema version.

## Rule-catalog JSON v1

`llmsafe --list-rules --format json` does not scan paths. It returns all built-in IDs in lexical order
with severity, family, description, and remediation. Its normative field shape is
[catalog-v1.schema.json](schemas/catalog-v1.schema.json).

Rule IDs are public API. A severity or semantic change must be called out in the changelog; IDs are not
silently reused for a different condition.

## SARIF 2.1.0

`--format sarif` emits SARIF 2.1.0 using the published SARIF schema URI. Findings become `results`, the
catalog supplies driver `rules`, stable fingerprints exclude line numbers, and dataflow evidence
becomes related locations. Cross-file evidence uses the related module's artifact URI.

SARIF consumers should use `ruleId`, locations, and standard levels rather than parsing the human
message. The output is deterministic for the same paths, source, configuration, and LLMSafe version.

## Exit codes

| Code | Meaning | Machine output |
| ---: | --- | --- |
| 0 | Scan completed and no finding met `--fail-on`; baseline writing also succeeds with 0 | Requested output is available |
| 1 | Scan completed and at least one non-baselined finding met the threshold | Requested output is available |
| 2 | Usage, policy, baseline, output-write, or scan error | Output may be unavailable when validation failed before scanning |

Configuration errors are written to stderr. Completed scan results are written to stdout or
`--output`. Integrations must branch on the exit code and must not treat code 2 as a clean scan.

## Composite Action mapping

The action preserves these codes as its `exit-code` output. `sarif-file` is empty when validation
failed before a report existed. This lets workflows upload only a real report and then enforce both
code 1 and code 2 explicitly.

## Compatibility tests

The test suite compares emitted top-level and item fields to the checked-in schemas, checks catalog
ordering, verifies SARIF determinism and version, exercises every exit-code class, and runs the
composite shell boundary. A schema change should begin with an explicit contract test and migration
note.
