"""OpenAI Agents SDK: model text is displayed, not treated as authority to execute."""

from agents import Agent, Runner, function_tool

agent = Agent(name="Repository assistant", instructions="Summarize repository status")


@function_tool
def describe_operation(operation: str) -> str:
    return f"Requested operation: {operation}"


async def inspect_repository() -> str:
    result = await Runner.run(agent, "Summarize the repository")
    return str(result.final_output)
