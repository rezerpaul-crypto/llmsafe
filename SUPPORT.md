# Support

LLMSafe is a volunteer-maintained project. This page routes requests to the right place and sets
realistic expectations.

## Choose the right channel

| Need | Channel |
| --- | --- |
| Reproducible bug, false positive, or false negative | [Bug report](https://github.com/rezerpaul-crypto/llmsafe/issues/new?template=bug_report.yml) |
| Installation, configuration, or usage question | [Support question](https://github.com/rezerpaul-crypto/llmsafe/issues/new?template=support_question.yml) |
| New detection idea | [Rule proposal](https://github.com/rezerpaul-crypto/llmsafe/issues/new?template=rule_proposal.yml) |
| Public-project compatibility pilot | [Pilot request](https://github.com/rezerpaul-crypto/llmsafe/issues/new?template=pilot_request.yml) |
| Vulnerability in LLMSafe itself | [Private vulnerability report](https://github.com/rezerpaul-crypto/llmsafe/security/advisories/new) |
| Conduct concern | Private path in the [Code of Conduct](CODE_OF_CONDUCT.md) |

Search existing issues before opening a new one. Provide the LLMSafe and Python versions, a minimal
sanitized example, expected behavior, and actual behavior. Never post credentials, personal data,
private source code, or embargoed vulnerability details.

## Response expectations

The maintainer aims to triage public requests within seven days and security reports within the
targets in [SECURITY.md](SECURITY.md). These are volunteer-project targets, not service-level
agreements. Clear reproductions and small examples are usually handled first.

## Scope of support

Community support covers installation, documented configuration, scanner output, rule behavior,
and contribution workflows. The project cannot provide incident response, legal or compliance
certification, guaranteed detection, private code review, or custom rule development through the
public issue tracker.

Scanner findings are evidence for human review. They do not prove exploitability and should not be
treated as a substitute for a broader security program.

The bounded pilot program is described separately in [docs/pilot-program.md](docs/pilot-program.md).
Do not place private code, credentials, scan findings, or embargoed security information in a pilot
request.
