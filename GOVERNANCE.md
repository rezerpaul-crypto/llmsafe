# Governance

LLMSafe is a maintainer-led open-source project. This document explains who can make decisions,
how changes are reviewed, and how responsibility can expand as the community grows.

## Current maintainership

The current maintainer is [@rezerpaul-crypto](https://github.com/rezerpaul-crypto). The maintainer
is responsible for:

- triaging issues and reviewing pull requests;
- protecting rule quality, compatibility, and the public security boundary;
- documenting roadmap decisions and important tradeoffs;
- managing releases, credentials, advisories, and repository settings; and
- enforcing the [Code of Conduct](CODE_OF_CONDUCT.md).

This single-maintainer structure is an explicit current limitation. It does not give any employer,
sponsor, vendor, or AI provider authority over project decisions.

## Contributors

Anyone may propose an issue, rule, documentation change, benchmark case, or pull request. A
contributor does not need prior permission for a focused change, but discussing large or breaking
changes in an issue first avoids wasted work. Contributions are evaluated on technical merit,
security impact, test evidence, maintenance cost, and fit with the documented scope.

## Decision process

1. Normal decisions are discussed in a public issue or pull request.
2. The maintainer seeks practical consensus and asks for evidence when tradeoffs are disputed.
3. If consensus is not reached, the maintainer makes the decision and records the reasoning.
4. Vulnerability details, credentials, private code, and conduct reports stay in their private
   reporting channels.

Reversible decisions can be made quickly. Changes to stable rule identifiers, supported Python
versions, output formats, severity semantics, or the security model require explicit migration
notes and stronger evidence.

## Review and merge policy

Every merge must be scoped, understandable, and pass the required automated checks. Behavior
changes need tests; user-facing changes need documentation. Detection changes must explain likely
false positives and false negatives. The maintainer may close inactive or out-of-scope proposals
with a written reason, and contributors may ask for reconsideration with new evidence.

The project prefers pull requests even for maintainer changes so that CI results and decisions are
publicly reviewable. Emergency security fixes may use a private advisory and coordinated release.

## Releases

Only a maintainer may publish a release. Releases follow the documented process in
[docs/releasing.md](docs/releasing.md), use semantic versioning, include release notes, and must be
traceable to a reviewed commit. PyPI publishing credentials and GitHub environments remain limited
to maintainers responsible for the release.

## Becoming a maintainer

Maintainer access is earned through sustained, constructive contributions and demonstrated care
with security-sensitive material. Candidates should show reliable reviews or implementation work,
respect for project scope, and willingness to share maintenance duties. Existing maintainers invite
new maintainers in a public pull request that updates this document.

## Conflicts, inactivity, and succession

Maintainers disclose conflicts that could reasonably affect a decision and should seek another
reviewer when one is available. A maintainer who expects to be unavailable for more than 30 days
should post a repository notice when practical. If the project gains multiple maintainers, no sole
maintainer should control every release and private reporting path; this document will be updated
with quorum, removal, and succession rules before that transition.

## Changing this document

Governance changes use a public pull request and should remain open long enough for meaningful
review. Until there are multiple active maintainers, the current maintainer has final responsibility
for accepting the change and recording why.
