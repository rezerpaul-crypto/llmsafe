"""OpenAI Agents SDK: model text is displayed, not treated as authority to execute."""

from agents import Agent, Runner

agent = Agent(name="Repository assistant", instructions="Summarize repository status")


async def inspect_repository() -> str:
    result = await Runner.run(agent, "Summarize the repository")
    return str(result.final_output)
