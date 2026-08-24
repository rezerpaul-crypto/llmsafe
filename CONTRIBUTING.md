# Contributing to LLMSafe

Thank you for helping make AI and agentic applications safer. Small, focused pull requests are
easier to review and are especially valuable while the project is young.

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). The
[governance policy](GOVERNANCE.md) explains how decisions, reviews, and maintainer access work.

## Set up a development environment

Fork and clone the repository, then run:

```bash
python3 scripts/dev.py
```

This one command creates an isolated environment and runs lint, tests, coverage, the benchmark, a
CLI smoke test, and LLMSafe's self-scan. It does not require shell activation. See the
[development workflow](docs/development.md) for repeat runs, Windows instructions, and individual
commands.

LLMSafe supports Python 3.9 through 3.14. CI runs the same contributor workflow on every supported
version.

## Proposing a rule

Read the [rule-authoring guide](docs/rule-authoring.md) for the complete workflow and a tested
vulnerable/safe/edge-case example.

A useful rule should include:

1. A concrete security risk and realistic AI/agent use case.
2. A stable ID, title, severity, explanation, and remediation.
3. Tests for vulnerable, safe, and edge-case inputs.
4. A matching entry in `llmsafe/catalog.py` with stable public metadata.
5. A low-noise detection strategy; structural parsing is preferred when practical.
6. A README update describing the rule.
7. A benchmark case when the rule represents a core AI/agent security scenario.

Never commit a real credential in a test fixture. Construct realistic-looking values at test
runtime or use unmistakable placeholders.

## Pull requests

- Keep each pull request focused on one concern.
- Add or update tests for behavior changes.
- Run `python3 scripts/dev.py --check-only` locally.
- Keep the curated benchmark at 100% expected-signal recall with no unexpected findings.
- Explain important false-positive or compatibility tradeoffs in the description.
- Do not reduce the coverage threshold to make a change pass.

## Rule design principles

- Prefer syntax trees and data-flow evidence over broad keyword matching.
- Report the dangerous operation, not every intermediate assignment.
- Make remediation specific enough to act on.
- Keep rule identifiers stable after release.
- Treat findings as evidence for review, not proof that an application is exploitable.

## Commit and release hygiene

Use focused, imperative commit messages such as `feat: detect tainted tool dispatch`. Maintainers
update the changelog, version, and release notes when preparing a release; contributors should
not bump the version unless asked.

By contributing, you agree that your contribution is licensed under the MIT License.

## Issues and security reports

Public issues are appropriate for bugs, false positives, false negatives, documentation, and rule
ideas. Use [SUPPORT.md](SUPPORT.md) to choose the correct issue form. Follow
[SECURITY.md](SECURITY.md) for vulnerabilities that should be reported privately. Never post real
credentials, private source code, personal data, or embargoed vulnerability details.
