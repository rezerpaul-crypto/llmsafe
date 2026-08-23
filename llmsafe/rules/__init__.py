"""Built-in LLMSafe rules."""

from llmsafe.rules.eval import DangerousPythonRule
from llmsafe.rules.mcp import MCPConfigRule
from llmsafe.rules.prompts import DynamicSystemPromptRule
from llmsafe.rules.secrets import SecretRule
from llmsafe.rules.shell import ShellExecutionRule

__all__ = [
    "DangerousPythonRule",
    "DynamicSystemPromptRule",
    "MCPConfigRule",
    "SecretRule",
    "ShellExecutionRule",
]
