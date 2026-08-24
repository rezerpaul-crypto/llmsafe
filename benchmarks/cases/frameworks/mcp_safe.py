"""MCP Python SDK v2: the server exposes one fixed, bounded operation."""

import subprocess

from mcp.server import MCPServer

mcp = MCPServer("Repository tools")


@mcp.tool()
def repository_status() -> str:
    return subprocess.check_output(["git", "status", "--short"], text=True)
