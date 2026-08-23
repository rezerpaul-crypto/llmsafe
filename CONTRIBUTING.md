# Contributing to LLMSafe

Thank you for helping make AI and agentic applications safer. Small, focused pull requests are
easier to review and are especially valuable while the project is young.

## Set up a development environment

Fork and clone the repository, then run:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
ruff check .
pytest --cov=llmsafe --cov-report=term-missing
python -m benchmarks.run
llmsafe . --format sarif --output llmsafe.sarif
```

Python 3.9 is the minimum supported version. New code must work on both Python 3.9 and the newest
version tested in CI.

## Proposing a rule

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
- Run the lint and test commands locally.
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
ideas. Follow [SECURITY.md](SECURITY.md) for vulnerabilities that should be reported privately.
