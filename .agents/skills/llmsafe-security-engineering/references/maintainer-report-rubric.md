# Private report: usefulness and publication gate

A maintainer should learn what risk exists, why it matters, and how to fix or verify it. The report is **not** a scanner printout and cannot prove that software is secure. Prepare only for LLMSafe-owned examples or expressly authorized project scopes. Do not send reports or request endorsements automatically.

## Each finding must contain

- **Context**: authorized repository/immutable target commit, exact file/line, scanner version/commit, configuration/command, scan result exit code, exclusions and skipped/error counts.
- **Specific assertion**: exact rule ID; static API/config signal versus demonstrated untrusted source→propagation→sink; trust boundary and the sensitive sink parameter.
- **Impact and prerequisites**: plausible consequence, necessary attacker control / runtime privileges, existing mitigations and uncertainty. Never convert `eval()`, `shell=True`, or a dangerous tool class directly into a claim of remote code execution.
- **Review classification**: one of TRUE POSITIVE (relevant boundary requiring review), FALSE POSITIVE (claimed condition contradicted), CONTEXT DEPENDENT (authorization/runtime matters), DUPLICATE, TOOL ERROR. Severity and confidence are distinct; `unverified` is not a positive verdict.
- **Action**: a specific least-privilege, typed-validation, parameterization, fixed command, sandbox/approval, or boundary-hardening change appropriate to the site. Provide minimal non-executing reproduction and exact retest; avoid intrusive proof-of-concept payloads.
- **Evidence**: safe excerpt or redacted path and a trace the maintainer can follow. Do not copy tokens, personal data, unpublished source, or secrets into reports.

## Report outline

1. Confidential title and scoped authorization (do not infer approval from public visibility).
2. 90-second summary: what was scanned, what was **not**, 1–3 highest-impact actionable points or "no validated actionable findings".
3. Environment and repeatability: tool+target SHA, command, rule/config, scan completeness, elapsed time, JSON/SARIF output hashes, number of findings reviewed.
4. Ranked **validated** observations, separately from unverified/context-dependent patterns; findings table lists ID, evidence, severity, confidence and owner action.
5. Per finding: trust-boundary diagram in words, safe proof, assumptions, impact, fix with test/retest, remaining uncertainty.
6. False positives, duplicates, blindspots, unsupported framework paths, exclusions and skipped-file caveats.
7. Three realistic next steps and private feedback questions about usefulness, noise, unsupported cases. Do not request a follow, rating, marketing quote, or paid upgrade as a condition of free work.
8. Redaction/disclosure metadata; maintainers control any public case study or testimonial separately.

## Hard release gate

Do not send a report to a project when any of these applies:
- No explicit approved scope/contact route or unresolved disclosure issue.
- Only grep/AST fragments instead of an accurately labeled scoped scan, with no meaningful validated risk or maintainer benefit.
- Source/control/impact is guessed, evidence is not reproducible, potentially sensitive data is exposed, or remediation is generic.
- Scan errors/skips are hidden or exit `2` is treated as success.
- Critical findings lack independent review, or classification and limitations are omitted.

## Quantifying value without inflated claims

Record: findings reviewed / total; true positive / false positive / context dependent / duplicate / tool error, with denominator; confirmed fix suggestions; hours to reproduce; maintainer acceptance after **voluntary** response. Never extrapolate from a hand-picked test corpus to population-wide recall or claimed exploit counts.

A report can still add value with **zero confirmed vulnerabilities** when it clearly proves narrower control coverage, identifies a real blindspot with actionable mitigation, or saves verifiable triage effort. Otherwise, mark it internal-only and improve LLMSafe.
