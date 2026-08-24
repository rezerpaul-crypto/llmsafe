# LLMSafe compatibility pilot

LLMSafe is inviting maintainers of public Python AI and agent projects to test the
[`v0.3.0rc1`](https://github.com/rezerpaul-crypto/llmsafe/releases/tag/v0.3.0rc1) pilot release.
The first five accepted projects receive a free, bounded compatibility review designed to improve
both the participating project and LLMSafe's real-world signal quality.

The pilot is an early open-source compatibility exercise. It is not a penetration test, security
certification, compliance assessment, or guarantee that an application is secure.

## What the pilot includes

- one public repository at one immutable commit;
- an agreed Python AI, agent, MCP, model-output, or tool-calling scenario;
- a local LLMSafe scan without credentials, cloud access, deployment, or model execution;
- manual review of every reported result in the agreed scope;
- a concise private report covering useful signals, likely false positives, unsupported patterns,
  limitations, and practical next steps;
- exact reproduction commands and an optional short technical handoff;
- an optional integration proposal only when the maintainer asks for one.

The project remains in control of scope, disclosure, and whether any integration is proposed.

## What it does not include

- access to production systems, model accounts, databases, credentials, or cloud subscriptions;
- review of private source code during this initial public-project pilot;
- runtime testing, exploitation, incident response, dependency auditing, or legal advice;
- an assertion that every finding is exploitable or that a clean scan proves safety;
- automatic publication of findings, project names, results, quotes, logos, or case studies;
- a requirement to install LLMSafe in CI, endorse it, or make a public contribution.

LLMSafe complements general static analysis, dependency scanning, human review, and runtime
controls. Its current framework coverage and analysis boundaries are documented in the
[framework matrix](framework-coverage.md), [threat model](threat-model.md), and
[cross-file analysis guide](cross-file-analysis.md).

## Privacy and disclosure

The scan runs locally. Source code is not uploaded to a model or external analysis service. The
pilot requires no API keys or deployed access.

The public intake issue contains only a repository URL, proposed revision, and compatibility
scenario. Never place private code, credentials, personal data, scan output, or suspected
vulnerabilities in that issue.

Results are shared privately through a maintainer-approved route. If review identifies a possible
security vulnerability, public discussion stops and the project's published security policy is
followed. Participation does not grant permission to publish findings or describe the project as an
LLMSafe user. Project naming, links, results, quotes, integrations, and case studies each require
separate explicit approval.

## Process and timing

1. A maintainer or authorized project representative submits a
   [pilot request](https://github.com/rezerpaul-crypto/llmsafe/issues/new?template=pilot_request.yml)
   containing no sensitive material.
2. LLMSafe confirms fit, the exact repository commit, the bounded scenario, exclusions, and the
   project's private reporting instructions.
3. The maintainer explicitly approves the scope before project-specific results are produced.
4. LLMSafe runs the scan, manually reviews the output, and aims to deliver the private report within
   two working days after scope agreement. This is a volunteer target, not a service-level
   agreement.
5. The maintainer can reproduce the run and report useful signals, noise, missing patterns, and
   installation friction.
6. Any fix, public integration, project name, quote, or case study is considered separately and
   proceeds only with explicit consent.

A decline ends the process. Either side may stop the pilot at any time.

## Reproduce the pilot release

Python 3.9 or newer is required:

```bash
python3 -m venv .llmsafe-venv
source .llmsafe-venv/bin/activate
python -m pip install --pre "llmsafe==0.3.0rc1"
llmsafe --version
llmsafe . --format json --output llmsafe.json
```

LLMSafe returns exit code `1` when a finding reaches the configured threshold and exit code `2` for
configuration, target, or processing errors. Neither code should be hidden or interpreted as a
clean result. Review the [five-minute demo](demo.md) before scanning a project if you want a
credential-free walkthrough.

## Request a pilot

Before submitting, confirm that:

- the project is public, Python-based, and involves AI agents, model output, MCP, or tool use;
- you maintain the project or are authorized to discuss a pilot for it;
- one specific compatibility or trust-boundary question can be named;
- the request contains no sensitive material;
- the project has a private route for possible security observations;
- you understand that participation and public disclosure are separate decisions.

If those conditions are met, submit the
[compatibility pilot request](https://github.com/rezerpaul-crypto/llmsafe/issues/new?template=pilot_request.yml).
For ordinary installation or scanner questions, use the routes in the [support policy](../SUPPORT.md).
