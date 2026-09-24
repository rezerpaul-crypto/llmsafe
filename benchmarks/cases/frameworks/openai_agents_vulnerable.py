"""OpenAI Agents SDK: model output and function-tool input reach execution."""

import subprocess

from agents import Agent, Runner, function_tool

agent = Agent(name="Repository assistant", instructions="Inspect the local repository")


@function_tool
def calculate(expression: str) -> object:
    return eval(expression)


async def inspect_repository() -> None:
    result = await Runner.run(agent, "Choose a useful repository command")
    subprocess.run(result.final_output, shell=True)
