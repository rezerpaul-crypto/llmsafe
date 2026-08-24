# Real-world benchmark protocol

Status: protocol only. No third-party repository has been enrolled or measured under this protocol.

This protocol must be approved before selecting repositories or running comparative measurements. It
separates a reproducible engineering study from promotional claims and protects maintainers when a
scan reveals a potentially exploitable issue.

## Research questions

1. Which LLMSafe rule signals appear in real Python AI or agent repositories?
2. What fraction of a manually reviewed sample is useful, a false positive, unclear, or duplicate?
3. Which relevant trust boundaries are missed in a documented ground-truth sample?
4. How do runtime, errors, and actionable output compare under equivalent scope and configuration?

The study does not attempt to estimate all-vulnerability recall or prove that a repository is secure.

## Repository eligibility

A repository may enter the corpus only when all of the following are recorded:

- public source and an OSI-approved or otherwise clearly scannable license;
- Python AI, agent, tool-use, or MCP code relevant to the research questions;
- an immutable commit hash and retrieval date;
- an identified private security-contact path;
- explicit maintainer opt-in for the benchmark, even when the license permits local scanning;
- no known embargo, active incident, or request not to perform security research.

Select up to ten repositories across at least three framework families. Do not choose repositories
because a preliminary scan produced favorable numbers. Record rejected candidates and reasons before
measurement to make selection bias visible.

## Consent and disclosure

Consent to scan is separate from consent to publish a name, result, quote, logo, or code excerpt. The
corpus register records each permission independently.

Potential vulnerabilities are sent privately to the recorded security contact. Public reporting is
paused until the maintainer confirms remediation or a mutually agreed disclosure date. If contact is
lost, follow the repository security policy; do not publish exploit details merely to finish the
benchmark.

## Frozen environment

For every run, record:

- repository URL only when publication consent permits, otherwise an internal identifier;
- commit SHA, license, selected paths, exclusions, and generated-file policy;
- tool name, exact version or commit, configuration, command, Python version, OS, and hardware class;
- start/end timestamp, wall-clock duration, exit code, scanned/skipped file counts, and errors;
- SHA-256 hashes of raw machine outputs.

Runs use fresh isolated environments with network access disabled after installation. Tools receive
the same included source tree. Caches are either cold for all runs or explicitly reported.

## Ground truth and sampling

Ground truth is not the union of tool output. Before reviewing tool identities, two reviewers define a
set of trust-boundary scenarios from code and project documentation. Each scenario records source,
propagation, sink, authorization boundary, and why it is security relevant.

When complete manual review is impractical, sample deterministically:

1. all critical signals;
2. all signals from rules with five or fewer results;
3. a hash-seeded sample from each remaining rule;
4. at least one safe counterpart near every confirmed scenario where available.

Publish the seed, sampling algorithm, sample sizes, reviewer disagreements, and adjudication method.

## Classification rubric

Each reviewed signal receives exactly one primary label:

| Label | Definition |
| --- | --- |
| True positive | The reported source-to-sink or dangerous configuration exists and requires security review |
| False positive | The claimed condition is absent or contradicted by static facts available to the scanner |
| Context dependent | The condition exists, but runtime authorization or deployment facts determine impact |
| Duplicate | The same root condition is already represented by another counted signal |
| Tool error | Parsing, traversal, crash, timeout, or malformed output prevents classification |

Severity agreement and remediation usefulness are recorded separately. A finding is not labeled true
merely because the underlying API is dangerous.

## Metrics

Report raw counts and denominators before rates:

- reviewed true positives, false positives, context-dependent results, duplicates, and tool errors;
- precision on the reviewed, non-duplicate classifiable sample;
- scenario recall only for the explicitly documented ground-truth scenarios;
- repositories completed, file counts, runtime, and peak memory when measurable;
- rule-level distribution and the number of repositories in which each rule appears.

Do not compare total finding counts as a quality ranking. Different tools have different scopes and
deduplication models.

## Fair comparison

Comparison tools must be credible, legally usable, and configured from their official documentation.
The report lists major scope differences before results. LLMSafe-specific fixtures are excluded from
the real-world comparison. Maintainers may review the protocol and their own classifications but do
not receive pressure to endorse conclusions.

## Data handling

- Raw source remains in temporary local workspaces and is not copied into this repository.
- Raw findings are private by default and may contain paths or sensitive context.
- Public datasets contain only consented, redacted records.
- Secrets are never included in logs, screenshots, issue bodies, or case studies.
- Internal identifiers and the consent register are stored outside the public repository.

## Reproducibility bundle

A publishable benchmark requires:

- this frozen protocol version;
- a consent-safe corpus manifest with revisions and license evidence;
- runner configuration and commands;
- output hashes and redacted classification records;
- calculation code and tests;
- limitations, deviations, missing data, and conflicts of interest;
- maintainer approval state for every named project.

## Stop conditions

Stop and do not publish when any repository lacks consent, a likely vulnerability is under disclosure,
raw data exposes sensitive material, comparison scope is materially unfair, reviewer disagreement is
unresolved, or the reproduction bundle cannot regenerate reported numbers.

## Pre-registration checklist

- [ ] Research questions and metrics frozen.
- [ ] Selection and rejection criteria frozen.
- [ ] Consent template and private contact path reviewed.
- [ ] Classification rubric trialed on LLMSafe's synthetic fixtures only.
- [ ] Comparison-tool configurations verified against official documentation.
- [ ] Raw-data location, retention window, and deletion owner recorded.
- [ ] Two reviewers identified; neither classification nor consent is fabricated.
- [ ] Security-disclosure escalation path ready.

Until every checked item is real, the benchmark remains a prepared protocol rather than Day-29
measurement evidence.
