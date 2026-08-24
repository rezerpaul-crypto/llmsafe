"""LangChain: an agent can select only a fixed, application-owned operation."""

import subprocess

from langchain.agents import create_agent

agent = create_agent(model="provider:model", tools=[])


def run() -> None:
    response = agent.invoke({"messages": [{"role": "user", "content": "Inspect git"}]})
    selection = response["messages"][-1].content
    if selection == "git_status":
        command = ["git", "status", "--short"]
    else:
        command = ["git", "diff", "--stat"]
    subprocess.run(command, check=True)
