# Threat model

LLMSafe reviews source and configuration for trust-boundary failures in AI-powered and agentic
applications.

## Protected assets

- Host execution environment and credentials
- Application and customer data
- Internal services reachable from the agent
- Tool permissions and approval boundaries
- Integrity of privileged system/developer instructions

## Untrusted inputs

- End-user messages, request parameters, uploaded or retrieved content
- Model and agent output, including tool names and arguments
- Remote MCP endpoints and server configuration
- Repository content that may accidentally contain credentials

Model output is treated as untrusted because it can be influenced by prompt injection, poisoned
retrieval content, model error, or an attacker controlling upstream context.

## Security boundaries

LLMSafe concentrates on transitions from untrusted data into:

- Python evaluation or execution
- Operating-system process and shell execution
- SQL query structure
- Outbound HTTP destinations
- Dynamic callable/tool selection
- High-impact agent tools and disabled human approvals
- Privileged prompt channels
- MCP transport and permission configuration

## Attacker capabilities

The modeled attacker may control application input or content consumed by an LLM and may attempt
to influence subsequent tool use. The scanner does not assume the attacker can modify trusted
source code, repository policy, or the CI environment.

## Out of scope

- Proving model alignment or prompt-injection resistance
- Runtime sandbox enforcement and authorization-server correctness
- Dependency vulnerabilities, malware, or supply-chain provenance
- Network-layer verification, DNS rebinding simulation, or penetration testing
- Cross-language dataflow and Python flows through wildcard/dynamic imports, methods, callable
  objects, runtime import hooks, or modules outside the selected project boundary
- Secrets already present in Git history after their working-tree value was removed

## Security posture

LLMSafe does not execute analyzed code, import the target project, or send code over the network.
Findings are evidence for human review. High-impact tools should still be sandboxed, least-privilege,
and protected by approval enforced outside model-controlled state.

Secret detection uses format and variable-name heuristics. Its generic placeholder policy applies
in every directory, so a real weak credential equal to an ignored marker can be missed. Legacy
substring placeholders can also hide longer generic values. The canonical AWS example exception
uses explicit token boundaries; it does not validate credentials or broaden the provider patterns.
See the [secret-rule policy](rules.md#secret-rules) for the exact exceptions. A clean scan is not
proof that a repository contains no credentials.
