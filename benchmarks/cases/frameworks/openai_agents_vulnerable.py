"""OpenAI Agents SDK: model output is executed through a shell."""

import subprocess

from agents import Agent, Runner

agent = Agent(name="Repository assistant", instructions="Inspect the local repository")


async def inspect_repository() -> None:
    result = await Runner.run(agent, "Choose a useful repository command")
    subprocess.run(result.final_output, shell=True)
