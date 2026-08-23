"""Stable metadata for LLMSafe's built-in rule identifiers."""

from dataclasses import dataclass
from typing import Any, Dict, Tuple

from llmsafe.models import Severity

CATALOG_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class RuleMetadata:
    """Public metadata describing one built-in rule."""

    rule_id: str
    title: str
    severity: Severity
    family: str
    description: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "family": self.family,
            "description": self.description,
            "remediation": self.remediation,
        }


RULE_CATALOG: Tuple[RuleMetadata, ...] = (
    RuleMetadata(
        "AGENT001",
        "High-impact tool exposed to an agent",
        Severity.HIGH,
        "agent",
        "Detects shell, terminal, execution, or Python REPL tools instantiated for agent use.",
        "Remove the tool or wrap it with strict arguments, sandboxing, and approval.",
    ),
    RuleMetadata(
        "AGENT002",
        "Dangerous agent capability explicitly enabled",
        Severity.HIGH,
        "agent",
        "Detects agent or tool calls that explicitly enable dangerous code or requests.",
        "Keep dangerous-code flags disabled and expose a narrow typed capability.",
    ),
    RuleMetadata(
        "AGENT003",
        "Human approval gate disabled",
        Severity.HIGH,
        "agent",
        "Detects agent, MCP, tool, or runner calls with a disabled human approval boundary.",
        "Require approval for high-impact tools and enforce it outside model control.",
    ),
    RuleMetadata(
        "FLOW001",
        "Untrusted data reaches code execution",
        Severity.CRITICAL,
        "dataflow",
        "Traces user- or model-controlled data into eval() or exec().",
        "Replace dynamic execution with a typed parser and an allow-listed operation.",
    ),
    RuleMetadata(
        "FLOW002",
        "Untrusted data reaches process execution",
        Severity.CRITICAL,
        "dataflow",
        "Traces user- or model-controlled data into operating-system process execution.",
        "Map requests to fixed executables and validated arguments; do not execute generated text.",
    ),
    RuleMetadata(
        "FLOW003",
        "Untrusted data reaches a SQL query",
        Severity.HIGH,
        "dataflow",
        "Traces user- or model-controlled data into SQL query text.",
        "Use a constant query with bound parameters and allow-list dynamic identifiers.",
    ),
    RuleMetadata(
        "FLOW004",
        "Untrusted data controls an outbound URL",
        Severity.HIGH,
        "dataflow",
        "Traces user- or model-controlled data into an outbound HTTP URL.",
        "Allow-list schemes and hosts, resolve DNS safely, and block private network ranges.",
    ),
    RuleMetadata(
        "FLOW005",
        "Untrusted data controls tool dispatch",
        Severity.HIGH,
        "dataflow",
        "Traces user- or model-controlled data into dynamic callable or tool selection.",
        "Resolve tool names through a fixed allow-list and enforce per-tool authorization.",
    ),
    RuleMetadata(
        "LLM001",
        "Dynamic data in privileged prompt",
        Severity.HIGH,
        "prompt",
        "Detects dynamic interpolation into system or developer instruction channels.",
        "Keep privileged instructions static and carry untrusted content in a user message.",
    ),
    RuleMetadata(
        "MCP001",
        "MCP server launched through a shell",
        Severity.HIGH,
        "mcp",
        "Detects MCP server commands launched through a command shell.",
        "Launch a fixed executable directly and pass each argument as a separate value.",
    ),
    RuleMetadata(
        "MCP002",
        "Unencrypted remote MCP transport",
        Severity.HIGH,
        "mcp",
        "Detects non-local MCP endpoints configured with unencrypted HTTP.",
        "Use HTTPS and authenticate the remote MCP endpoint.",
    ),
    RuleMetadata(
        "MCP003",
        "Unrestricted MCP tool access",
        Severity.HIGH,
        "mcp",
        "Detects MCP configurations that grant access to every available tool.",
        "Grant only the specific MCP tools required by the application.",
    ),
    RuleMetadata(
        "PY001",
        "Dynamic code evaluation",
        Severity.HIGH,
        "python",
        "Detects eval() calls even when static analysis cannot prove an untrusted source.",
        "Parse the expected data format explicitly; never pass model or user output to eval().",
    ),
    RuleMetadata(
        "PY002",
        "Dynamic code execution",
        Severity.CRITICAL,
        "python",
        "Detects exec() calls even when static analysis cannot prove an untrusted source.",
        "Replace dynamic execution with an allow-listed command or structured operation.",
    ),
    RuleMetadata(
        "PY003",
        "Unsafe deserialization",
        Severity.HIGH,
        "python",
        "Detects pickle deserialization that can execute code from crafted input.",
        "Use JSON or another non-executable format and validate the decoded schema.",
    ),
    RuleMetadata(
        "PY004",
        "Potentially unsafe YAML load",
        Severity.MEDIUM,
        "python",
        "Detects yaml.load() calls that may instantiate unsafe Python objects.",
        "Use yaml.safe_load() for data-only YAML.",
    ),
    RuleMetadata(
        "SECRET001",
        "OpenAI API key",
        Severity.CRITICAL,
        "secret",
        "Detects values matching an OpenAI API key format.",
        "Revoke the credential, remove it from Git history, and load a replacement securely.",
    ),
    RuleMetadata(
        "SECRET002",
        "AWS access key",
        Severity.CRITICAL,
        "secret",
        "Detects values matching an AWS access key identifier.",
        "Revoke the credential, remove it from Git history, and load a replacement securely.",
    ),
    RuleMetadata(
        "SECRET003",
        "GitHub token",
        Severity.CRITICAL,
        "secret",
        "Detects values matching a GitHub authentication token.",
        "Revoke the credential, remove it from Git history, and load a replacement securely.",
    ),
    RuleMetadata(
        "SECRET004",
        "Private key",
        Severity.CRITICAL,
        "secret",
        "Detects private-key headers committed to a scanned file.",
        "Revoke the key, remove it from Git history, and load a replacement securely.",
    ),
    RuleMetadata(
        "SECRET005",
        "Hard-coded credential",
        Severity.HIGH,
        "secret",
        "Detects literal values assigned to credential-like variables.",
        "Revoke the credential, remove it from Git history, and load a replacement securely.",
    ),
    RuleMetadata(
        "SHELL001",
        "Shell command execution",
        Severity.HIGH,
        "shell",
        "Detects os.system() command execution.",
        "Use subprocess.run() with an argument list, shell=False, and an allow-list.",
    ),
    RuleMetadata(
        "SHELL002",
        "Subprocess launched through a shell",
        Severity.HIGH,
        "shell",
        "Detects subprocess calls configured with shell=True.",
        "Pass an argument list with shell=False and allow-list commands and arguments.",
    ),
)


def _index_rules(rules: Tuple[RuleMetadata, ...]) -> Dict[str, RuleMetadata]:
    indexed = {rule.rule_id: rule for rule in rules}
    if len(indexed) != len(rules):
        raise RuntimeError("LLMSafe rule catalog contains duplicate identifiers")
    return indexed


RULES_BY_ID = _index_rules(RULE_CATALOG)
