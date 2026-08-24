# Framework coverage

LLMSafe scans source code; it does not import or run the application under review. Framework names
in this document therefore describe tested syntax and trust boundaries, not blanket support for
every feature of a framework.

The matrix is pinned to upstream source snapshots so fixtures can be updated deliberately when an
API changes.

| Ecosystem | Security boundary | Upstream syntax used as evidence | Current LLMSafe signal | Safe counterpart used in tests | Executable fixtures |
| --- | --- | --- | --- | --- | --- |
| OpenAI Agents SDK | Model or user data reaches a tool, shell, URL, query, or dynamic callable | [`Agent` and `Runner.run`](https://github.com/openai/openai-agents-python/blob/fe45b415e8d89db1c2011d1430631c0f894cb234/docs/running_agents.md) | `Runner.run()`, `run_sync()`, and `run_streamed()` results are model sources; generic dataflow then checks sensitive sinks. | Model text remains data; application-owned code retains execution authority. | [`openai_agents_vulnerable.py`](../benchmarks/cases/frameworks/openai_agents_vulnerable.py) / [`openai_agents_safe.py`](../benchmarks/cases/frameworks/openai_agents_safe.py) |
| Anthropic Python SDK | `messages.create()` output or a `tool_use` request reaches a high-impact operation | [Official tool-use example](https://github.com/anthropics/anthropic-sdk-python/blob/23cf4583e155fee089b7d2a8d5089980fa773e8e/examples/tools.py) | `.messages.create()` is a model source; source-to-code, process, SQL, URL, and dynamic-dispatch sinks are checked. | Match a narrow tool name and validate its arguments before calling a fixed function. | [`anthropic_vulnerable.py`](../benchmarks/cases/frameworks/anthropic_vulnerable.py) / [`anthropic_safe.py`](../benchmarks/cases/frameworks/anthropic_safe.py) |
| LangChain | Agent output or invocation data controls a tool or downstream sink | [`create_agent`, `@tool`, and `invoke`](https://github.com/Azure-Samples/python-ai-agent-frameworks-demos/blob/main/examples/langchainv1_tools.py) | `.invoke()` is a model source. High-impact tool classes and disabled approval keywords receive structural checks. | Convert an allowed selection to an application-owned fixed argument list. | [`langchain_vulnerable.py`](../benchmarks/cases/frameworks/langchain_vulnerable.py) / [`langchain_safe.py`](../benchmarks/cases/frameworks/langchain_safe.py) |
| PydanticAI | A registered tool performs a sensitive action without approval or validation | [`@agent.tool_plain` and `requires_approval`](https://github.com/pydantic/pydantic-ai/blob/5815470ac72356d164af57efdc41635e943170f1/docs/tools.md) | Explicit `requires_approval=False` on tool-like calls is checked. Generic dataflow covers user/model-like arguments inside tool functions. | `requires_approval=True`, typed arguments, bounded operations. | [`pydantic_ai_vulnerable.py`](../benchmarks/cases/frameworks/pydantic_ai_vulnerable.py) / [`pydantic_ai_safe.py`](../benchmarks/cases/frameworks/pydantic_ai_safe.py) |
| MCP Python SDK v2 | An MCP tool exposes process, filesystem, network, or dynamic execution to a remote caller | [`MCPServer`, `@mcp.tool()`, and `Client`](https://github.com/modelcontextprotocol/python-sdk/blob/57394b050dba9f48f8571d72bfac528722a6fb12/README.md) | Generic dataflow checks Python tool arguments; MCP JSON checks shell launch, plaintext remote transport, and wildcard grants. Dedicated Python decorator semantics remain future work. | Expose a fixed tool surface with validated arguments and fixed subprocess arguments. | [`mcp_vulnerable.py`](../benchmarks/cases/frameworks/mcp_vulnerable.py) / [`mcp_safe.py`](../benchmarks/cases/frameworks/mcp_safe.py) |

## What “covered” means

A framework fixture is covered only when a vulnerable example produces the expected stable rule IDs,
its safe counterpart produces none of those findings, and the pair runs in the benchmark suite.
Generic signals are useful, but they do not imply framework-specific semantics. The benchmark is the
executable source of truth.

## Non-goals

- Proving that a deployed agent is secure.
- Executing tools, contacting model providers, or requiring API credentials.
- Validating remote authorization policy or human approval services.
- Promising support for framework syntax that is not represented by a regression fixture.

## Updating the matrix

When an upstream API changes, update the pinned reference and the vulnerable/safe fixture in the same
pull request. Record the exact rule IDs expected from the vulnerable case and explain any intentionally
unsupported boundary in the pull request description.
