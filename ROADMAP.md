# Roadmap

LLMSafe develops in small, testable milestones. Public issues hold the acceptance criteria and
discussion for each item.

## v0.2.0 — Explainable agent security

- [x] Source-to-sink dataflow for code, shell, SQL, HTTP, and tool dispatch ([#1](https://github.com/rezerpaul-crypto/llmsafe/issues/1))
- [x] Agent-framework tools and approval gates ([#3](https://github.com/rezerpaul-crypto/llmsafe/issues/3))
- [x] TOML policy and SARIF 2.1.0 ([#4](https://github.com/rezerpaul-crypto/llmsafe/issues/4))
- [x] Vulnerable/safe regression benchmark ([#5](https://github.com/rezerpaul-crypto/llmsafe/issues/5))
- [x] Composite GitHub Action and pre-commit metadata ([#2](https://github.com/rezerpaul-crypto/llmsafe/issues/2))

## Next

- Cross-file import resolution and project-wide function summaries
- JavaScript/TypeScript agent and MCP analysis
- Framework fixture matrix for OpenAI Agents SDK, Anthropic, LangChain, and common MCP servers
- Standardized rule metadata export and documentation generation
- Baseline files for incremental adoption in existing repositories
- Performance corpus and false-positive measurements on opt-in open-source projects

Priorities may change based on reproducible bug reports and real adoption feedback.
