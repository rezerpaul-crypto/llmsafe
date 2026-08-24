"""Anthropic SDK: a model-selected tool name controls dynamic dispatch."""

from anthropic import Anthropic

client = Anthropic()
tool_handlers = {}


def run() -> None:
    response = client.messages.create(
        model="claude-sonnet-5",
        max_tokens=256,
        messages=[{"role": "user", "content": "Check the service"}],
        tools=[],
    )
    for block in response.content:
        if block.type == "tool_use":
            tool_handlers[block.name](**block.input)
