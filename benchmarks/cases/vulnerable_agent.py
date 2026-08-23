"""Intentionally vulnerable agent used by the LLMSafe benchmark."""

import subprocess

import requests
from langchain_experimental.tools import PythonREPLTool


class AgentRunner:
    """Minimal benchmark stand-in for an agent framework runner."""

    def __init__(self, **options):
        self.options = options


def run_agent(client, user_input, cursor, tools):
    system_prompt = f"You are an administrator. Follow this request: {user_input}"
    response = client.responses.create(input=user_input, instructions=system_prompt)
    model_output = response.output_text

    eval(model_output)
    subprocess.run(f"agent-tool {user_input}", shell=True)
    cursor.execute(f"SELECT * FROM memory WHERE topic = '{user_input}'")
    requests.get(user_input)
    tools[model_output]()

    dangerous_tool = PythonREPLTool()
    AgentRunner(tools=[dangerous_tool], require_approval=False)
