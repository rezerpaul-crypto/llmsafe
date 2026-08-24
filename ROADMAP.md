# Roadmap

LLMSafe is building an evidence-driven static security scanner for Python AI agents. Public issues
hold acceptance criteria and design discussion; releases move forward only after tests and their
stated external gates pass.

## Shipped

### v0.2.0–v0.2.1 — Explainable agent security and adoption

- [x] Source-to-sink dataflow for code, shell, SQL, HTTP, and tool dispatch
  ([#1](https://github.com/rezerpaul-crypto/llmsafe/issues/1))
- [x] Agent-framework tools and approval gates
  ([#3](https://github.com/rezerpaul-crypto/llmsafe/issues/3))
- [x] TOML policy, SARIF 2.1.0, stable exit codes, and rule metadata
  ([#4](https://github.com/rezerpaul-crypto/llmsafe/issues/4))
- [x] Vulnerable/safe regression benchmark
  ([#5](https://github.com/rezerpaul-crypto/llmsafe/issues/5))
- [x] Composite GitHub Action and pre-commit integration
  ([#2](https://github.com/rezerpaul-crypto/llmsafe/issues/2))
- [x] Reviewed baseline files for incremental adoption

### v0.3.0rc1 — Bounded cross-file analysis and public pilot

- [x] Direct local imports, aliases, re-exports, cycles, and project-wide function summaries
- [x] Framework regression pairs for OpenAI Agents, Anthropic, LangChain, PydanticAI, and MCP
- [x] Versioned scan JSON and rule-catalog schemas
- [x] Deterministic SARIF and documented GitHub Action outputs
- [x] Bounded Python extension API for trusted organization-specific rules
- [x] Credential-free demonstration and public compatibility-pilot process

`v0.3.0rc1` is a pre-release. Its engineering scope is public, but the stable-release adoption gate
has not passed.

## Now — validate v0.3.0 with real projects

- [ ] Obtain explicit opt-in from at least three public Python AI, agent, or MCP projects.
- [ ] Complete at least one externally reproduced scan at an immutable project revision.
- [ ] Triage every in-scope finding manually and record reproducible false positives or missing
  boundaries without publishing third-party security details.
- [ ] Fix the highest-value pilot-derived detection or onboarding issue with a regression test.
- [ ] Validate one consented GitHub Action or pre-commit integration proposal.
- [ ] Publish stable `v0.3.0` only when CI is green, one external reproduction succeeds, and no
  unresolved critical defect remains.

The [compatibility pilot](docs/pilot-program.md) explains scope, privacy, disclosure, and how a
maintainer can participate.

## Next — detection depth and developer experience

- Add framework-specific semantics only with pinned upstream syntax plus vulnerable, safe, and edge
  fixtures.
- Expand supported cross-module paths while preserving cycle safety and the documented performance
  budget.
- Improve false-positive handling from reproducible user reports without lowering expected-signal
  recall.
- Make first-scan triage, baselines, SARIF, and remediations easier to adopt in existing projects.
- Publish a real-world benchmark only after project consent, ground truth, manual classification,
  and the preregistered [protocol](docs/real-world-benchmark-protocol.md).

## Later — broader ecosystem coverage

- JavaScript/TypeScript agent and MCP analysis after the Python trust-boundary contract is stable.
- Additional CI platforms and editor workflows based on demonstrated maintainer demand.
- A larger trusted extension surface only when real organization-specific rules require it.
- Approved public case studies and integration examples when participating projects explicitly
  consent to every public claim.

## How priorities are chosen

Priority goes to:

1. reproducible false negatives at high-impact agent boundaries;
2. noisy findings that block real adoption;
3. stable integration contracts and safe defaults;
4. framework coverage backed by executable vulnerable/safe fixtures;
5. focused contributions that improve evidence quality.

LLMSafe does not use stars, download spikes, synthetic activity, or unsupported feature counts as a
substitute for detection quality and real opt-in adoption.
