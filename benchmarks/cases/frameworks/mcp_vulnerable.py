"""MCP Python SDK v2: a remote tool argument reaches a shell."""

import subprocess

from mcp.server import MCPServer

mcp = MCPServer("Repository tools")


@mcp.tool()
def run_command(command: str) -> str:
    return subprocess.check_output(command, shell=True, text=True)
