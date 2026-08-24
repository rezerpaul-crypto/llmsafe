"""LangChain: an agent result is interpolated into a shell command."""

import subprocess

from langchain.agents import create_agent

agent = create_agent(model="provider:model", tools=[])


def run() -> None:
    response = agent.invoke({"messages": [{"role": "user", "content": "Inspect git"}]})
    command = response["messages"][-1].content
    subprocess.run(command, shell=True)
