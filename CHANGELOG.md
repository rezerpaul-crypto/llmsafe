# Changelog

All notable changes to LLMSafe will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project intends
to use [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Fixed-point summaries for direct calls to local Python helpers, including positional,
  keyword-only, variadic, and unpacked keyword argument mapping with cross-boundary evidence.
- Vulnerable and safe inter-procedural benchmark cases, increasing the corpus to 18 expected rule
  signals across five cases.

## [0.2.1] - 2026-08-23

### Added

- Reproducible package builds and validation in CI.
- Trusted Publishing workflow for passwordless PyPI releases with provenance attestations.
- PyPI project metadata and maintainer release documentation.

### Changed

- Packaging metadata now uses an SPDX license expression and declares Python 3.13 and 3.14.

## [0.2.0] - 2026-08-23

### Added

- Intra-procedural taint analysis from user/model sources to code, shell, SQL, URL, and dynamic
  tool-dispatch sinks, including source-to-sink evidence.
- Structural agent-framework rules for dangerous execution tools and disabled approval gates.
- Repository policy discovery through `.llmsafe.toml` and `[tool.llmsafe]`.
- Deterministic SARIF 2.1.0 output with GitHub-compatible fingerprints and evidence locations.
- Reusable composite GitHub Action, Code Scanning workflow, and pre-commit hook metadata.
- Checked-in vulnerable/safe agent benchmark with 13 expected rule signals.
- Public architecture, threat-model, rule-catalog, configuration, and benchmark documentation.

### Changed

- CI now tests Python 3.9, 3.12, and 3.14 with current Node 24-based GitHub Actions.
- Text and JSON findings now include trace evidence where dataflow is available.

## [0.1.0] - 2026-08-23

### Added

- Dependency-free Python CLI with text and JSON output.
- Recursive scanner with exclusions, binary/size limits, and inline suppressions.
- Rules for credentials, dynamic execution, unsafe shell calls, privileged prompt interpolation,
  and risky MCP configuration.
- Unit tests, coverage policy, Ruff configuration, and GitHub Actions CI.
- Security policy, contribution guide, examples, and MIT license.
