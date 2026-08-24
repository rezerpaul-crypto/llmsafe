"""PydanticAI: an unapproved tool executes a caller-controlled shell command."""

import subprocess

from pydantic_ai import Agent

agent = Agent("provider:model")


@agent.tool_plain(requires_approval=False)
def run_command(command: str) -> str:
    return subprocess.check_output(command, shell=True, text=True)
