# Changelog

All notable changes to LLMSafe will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project intends
to use [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Dataflow sinks now bind security-sensitive positional, keyword, and unpacked-keyword arguments
  by API signature. This detects keyword-based process and SQL inputs plus the URL in generic HTTP
  request and streaming calls without treating tainted ancillary options as the sink value.
- Dataflow source and sink matching now resolves unambiguous external module and symbol import
  aliases while rejecting rebound, parameter-shadowed, or conflicting bindings.

## [0.3.0rc1] - 2026-08-24

### Added

- Fixed-point summaries for direct calls to local Python helpers, including positional,
  keyword-only, variadic, and unpacked keyword argument mapping with cross-boundary evidence.
- Bounded local import resolution and cross-module dataflow for relative and absolute imports,
  aliases, direct re-exports, keyword arguments, and safe import cycles.
- Cross-file evidence paths in JSON and SARIF related locations.
- Paired regression fixtures for current OpenAI Agents, Anthropic, LangChain, PydanticAI, and MCP
  Python syntax, increasing the benchmark to 28 expected signals across 15 cases.
- OpenAI Agents `Runner.run()`, `run_sync()`, and `run_streamed()` model-source recognition.
- Versioned machine-readable metadata for all 23 built-in rules through `--list-rules`, with the
  same catalog powering SARIF rule descriptors.
- Deterministic, duplicate-aware baseline files for incremental adoption through the CLI,
  repository policy, JSON/SARIF summaries, and composite GitHub Action.
- One-command contributor workflow, rule-authoring example, five-minute demo, framework coverage
  matrix, governance, support, and maintainer documentation.
- Versioned scan-JSON and rule-catalog schemas, a documented exit-code contract, and end-to-end
  composite Action tests.
- Verified pipx, full-project pre-commit, and reviewed-baseline adoption paths.
- A repeatable 500-module performance corpus and dependency-worklist summary propagation.
- A bounded `llmsafe.api` surface for explicitly supplied organization-specific rules, without
  dynamic plugin discovery.

### Changed

- Project scans collect selected files before rule execution so project-aware rules can analyze a
  bounded local graph without importing or running target code.
- File symlinks are skipped so a selected tree cannot silently expand through a linked file.
- Scan JSON now declares `schema_version: 1`; cross-file text and SARIF evidence identify the sink
  artifact.
- Third-party Actions are pinned to full commit SHAs, checkout credentials are never persisted, and
  SARIF upload permission is isolated from the job that executes repository code.

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
