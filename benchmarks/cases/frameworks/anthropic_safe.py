"""Anthropic SDK: tool names are matched to an explicit operation."""

from anthropic import Anthropic

client = Anthropic()


def get_service_status(service: str) -> str:
    return f"Status requested for {service}"


def run() -> None:
    response = client.messages.create(
        model="claude-sonnet-5",
        max_tokens=256,
        messages=[{"role": "user", "content": "Check the service"}],
        tools=[],
    )
    for block in response.content:
        if block.type == "tool_use" and block.name == "get_service_status":
            service = str(block.input.get("service", "unknown"))
            get_service_status(service)
