"""PydanticAI: a high-impact tool requires approval and runs fixed arguments."""

import subprocess

from pydantic_ai import Agent

agent = Agent("provider:model")


@agent.tool_plain(requires_approval=True)
def repository_status() -> str:
    return subprocess.check_output(["git", "status", "--short"], text=True)
