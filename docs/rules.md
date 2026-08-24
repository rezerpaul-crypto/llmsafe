# Rule catalog

Rule IDs are stable public identifiers. Severity represents potential impact when the pattern is
reachable with attacker- or model-controlled data; application context can change the final risk.
Contributors should start with the [rule-authoring guide](rule-authoring.md).

## Machine-readable catalog

The built-in metadata is available without scanning a repository:

```bash
llmsafe --list-rules
llmsafe --list-rules --format json --output llmsafe-rules.json
```

JSON catalog schema version 1 contains the LLMSafe version and a deterministically ordered `rules`
array. Each rule has `id`, `title`, `severity`, `family`, `description`, and `remediation` fields.
SARIF reports use this same metadata source, preventing integration output from drifting away from
the public catalog.

## Dataflow rules

| ID | Severity | Detects | Primary remediation |
| --- | --- | --- | --- |
| `FLOW001` | Critical | User/model data reaching `eval` or `exec` | Parse typed data and map to allow-listed operations |
| `FLOW002` | Critical | User/model data reaching process execution | Fixed executable plus validated argument list |
| `FLOW003` | High | User/model data changing SQL text | Constant query and bound parameters |
| `FLOW004` | High | User/model data controlling outbound HTTP URL | Allow-list scheme/host and block private ranges |
| `FLOW005` | High | User/model data selecting a callable | Fixed tool registry plus per-tool authorization |

Dataflow findings include evidence locations for sources and the sink. Direct calls to local
module-level helpers are summarized to a fixed point, allowing a finding to cross multiple wrapper
functions while still reporting the helper boundary.

## Agent-framework rules

| ID | Severity | Detects |
| --- | --- | --- |
| `AGENT001` | High | Shell, terminal, exec, or Python REPL tools instantiated for agent use |
| `AGENT002` | High | Explicit `allow_dangerous_code` or `allow_dangerous_requests` flags |
| `AGENT003` | High | Agent/tool/runner calls with a disabled approval gate |

The import resolver follows direct imports and aliases, so `PythonREPLTool as PythonTool` remains
detectable. It does not resolve re-exports across project files.

## Secret rules

| ID | Severity | Detects |
| --- | --- | --- |
| `SECRET001` | Critical | OpenAI-style API keys |
| `SECRET002` | Critical | AWS access key IDs |
| `SECRET003` | Critical | GitHub tokens |
| `SECRET004` | Critical | Private-key headers |
| `SECRET005` | High | Literal values assigned to credential-like variables |

Reported messages never include the matched credential. Placeholder values such as `change-me` and
`your-api-key-here` are ignored by the generic credential rule.

## Python execution rules

| ID | Severity | Detects |
| --- | --- | --- |
| `PY001` | High | `eval()` |
| `PY002` | Critical | `exec()` |
| `PY003` | High | `pickle.load()` and `pickle.loads()` |
| `PY004` | Medium | `yaml.load()` instead of data-only safe loading |

These rules report dangerous APIs even when dataflow cannot prove a trust-boundary path.

## Shell rules

| ID | Severity | Detects |
| --- | --- | --- |
| `SHELL001` | High | `os.system()` |
| `SHELL002` | High | `subprocess` calls with `shell=True` |

## Prompt rule

| ID | Severity | Detects |
| --- | --- | --- |
| `LLM001` | High | Dynamic interpolation into system/developer prompt variables or keywords |

This is a trust-boundary warning. Dynamic data should be carried in a separate user message rather
than merged into privileged instructions.

## MCP rules

| ID | Severity | Detects |
| --- | --- | --- |
| `MCP001` | High | MCP server launched through `sh -c`, PowerShell, or equivalent shell |
| `MCP002` | High | Non-local MCP endpoint using unencrypted HTTP |
| `MCP003` | High | MCP configuration allowing `*` or all tools |

MCP rules parse JSON and activate for MCP-named files or objects containing `mcpServers`.

## Suppression policy

Use `llmsafe: ignore[RULE_ID]` only after documenting why a safer construction is not practical.
Suppressions can be placed on the finding line or immediately above it. Repository-wide rule
disablement belongs in policy and should receive the same review as code changes.
