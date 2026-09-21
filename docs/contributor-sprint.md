# Contributor sprint

LLMSafe welcomes focused contributions that improve real security behavior, test evidence,
integrations, or technical documentation. This page is the shortest path from an open task to a
reviewable pull request without duplicating somebody else's work.

## Start in about 15 minutes

1. Choose one open [`good first issue`](https://github.com/rezerpaul-crypto/llmsafe/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22good%20first%20issue%22).
2. Read the complete issue and its comments, then check for a linked or competing pull request.
3. Comment with the issue number, your proposed boundary, and the tests you intend to add. Wait for
   maintainer confirmation when the issue contains a design gate.
4. Fork and clone LLMSafe, create a focused branch, and run `python3 scripts/dev.py` once.
5. Add the smallest vulnerable, safe, and adversarial regression cases that define the change.
6. Run `python3 scripts/dev.py --check-only`, then open one pull request that links or closes the
   issue and explains important false-positive or compatibility tradeoffs.

The first command creates an isolated environment and runs the same lint, tests, coverage,
benchmark, CLI smoke test, and self-scan used by CI. A contributor needs only one supported Python
version locally; GitHub checks the complete Python 3.9–3.14 matrix.

## Choose a contribution lane

| Lane | Good fit when you want to… | Browse |
| --- | --- | --- |
| Detection rule | improve a concrete false positive, false negative, or dangerous API boundary | [`rule`](https://github.com/rezerpaul-crypto/llmsafe/issues?q=is%3Aissue%20is%3Aopen%20label%3Arule) |
| MCP | classify MCP configuration or transport behavior precisely | [`mcp`](https://github.com/rezerpaul-crypto/llmsafe/issues?q=is%3Aissue%20is%3Aopen%20label%3Amcp) |
| CLI | improve actionable output without breaking JSON, SARIF, or exit-code contracts | [`cli`](https://github.com/rezerpaul-crypto/llmsafe/issues?q=is%3Aissue%20is%3Aopen%20label%3Acli) |
| Developer experience | remove a reproducible setup, test, or contributor-workflow problem | [`developer experience`](https://github.com/rezerpaul-crypto/llmsafe/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22developer%20experience%22) |
| CI and Windows | improve a cross-platform workflow while preserving least privilege | [`ci`](https://github.com/rezerpaul-crypto/llmsafe/issues?q=is%3Aissue%20is%3Aopen%20label%3Aci) · [`windows`](https://github.com/rezerpaul-crypto/llmsafe/issues?q=is%3Aissue%20is%3Aopen%20label%3Awindows) |
| Baselines | make reviewed suppressions and stale entries easier to maintain | [`baseline`](https://github.com/rezerpaul-crypto/llmsafe/issues?q=is%3Aissue%20is%3Aopen%20label%3Abaseline) |

For a new rule, read the [rule-authoring guide](rule-authoring.md) before proposing metadata or an
implementation. For setup details and individual commands, use the
[development workflow](development.md).

## Coordinate before coding

An issue comment is a coordination signal, not ownership of a task. It helps the maintainer prevent
two people from implementing the same change and confirm any public contract before code is written.

- Keep one pull request focused on one issue or one independently reviewable concern.
- Say promptly if you are no longer working on a claimed task so another contributor can proceed.
- Do not build on an open contributor branch unless its author and the maintainer agree.
- Do not add release, version, dependency, or unrelated refactoring changes to a contributor task.
- Ask in the issue when an acceptance criterion conflicts with current behavior; do not silently
  widen the scope.

## What makes a contribution substantive

A contribution is substantive when it delivers at least one complete, maintainable improvement:

- a detection or precision fix with vulnerable, safe, and adversarial tests;
- a framework fixture with an expected benchmark signal and a clean counterexample;
- a meaningful CI, packaging, performance, or integration improvement;
- a reproducible scanner diagnostic or compatibility fix; or
- substantial technical documentation whose examples or contracts are tested.

Typos, cosmetic churn, generated files, and several tiny pull requests split from one change are
welcome only when independently useful; they are not treated as several substantive contributions.

## Review contract

The maintainer reviews the exact pull-request head SHA, not only the latest visible diff. Review
checks include scope, behavior, tests, security boundaries, public compatibility, and the complete
quality workflow.

- During an active contributor sprint, the target is a first substantive maintainer response within
  24 hours. This is a volunteer-project target, not a service-level agreement.
- If GitHub shows **Awaiting approval** for a first-time contributor, do not close and reopen the
  pull request. The maintainer first inspects the workflow diff and exact head, then authorizes CI
  only when it is safe.
- Blocking findings identify behavior required before merge. Non-blocking suggestions are labelled
  as such and do not silently become merge requirements.
- A new commit invalidates earlier test evidence for the old head. The maintainer reruns the
  relevant gates before approval or merge.
- Passing CI is required but is not automatic approval; detection precision and security-relevant
  false negatives remain review decisions.

Contributors do not need to ping before 48 hours. If the target is missed, one concise comment on
the pull request is enough.

## Evidence expected by change type

| Change | Minimum evidence |
| --- | --- |
| Detection behavior | vulnerable, safe, and edge/adversarial cases; catalog and rule docs; false-positive/negative tradeoff |
| MCP or configuration | valid, invalid, malformed, deceptive, and unrelated inputs; no scanner crash |
| CLI or output | human output plus unchanged default JSON/SARIF/exit-code contracts unless the issue approves a versioned change |
| Workflow | read-only default permissions, full action SHA pins, no persisted checkout credentials, fork-safe secret boundary |
| Documentation | commands or examples checked against the current interface; every local link resolves |

Never lower the coverage threshold, delete a safe counterexample, or weaken an expected benchmark
signal to make a change pass.

## Security and privacy boundaries

Do not place credentials, private source code, personal data, real customer material, unpublished
scan results, or embargoed vulnerability details in an issue, fixture, commit, or pull request.
Report vulnerabilities in LLMSafe itself through the [private advisory route](../SECURITY.md).

LLMSafe tests must not import or execute scanned target code. Construct synthetic credential-like
values at test runtime or use unmistakable placeholders.

## After merge

The merged pull request remains the source of truth for authorship and technical credit. Maintainers
verify post-merge CI before recording the contribution. An issue claim, draft, open pull request, or
green check is work in progress and is not represented as a merged contribution.

Questions about setup or contribution mechanics belong in the
[support channel](../SUPPORT.md). Scope and design decisions stay on the relevant issue so future
contributors can find the reasoning.
