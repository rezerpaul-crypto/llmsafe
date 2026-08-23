"""Security checks for Model Context Protocol server configuration."""

import json
from pathlib import Path
from typing import Any, Dict, Iterable
from urllib.parse import urlparse

from llmsafe.models import Finding, Severity
from llmsafe.rules.base import line_containing


def _looks_like_mcp_config(path: Path, data: Any) -> bool:
    lowered = path.name.lower()
    return "mcp" in lowered or (
        isinstance(data, dict) and isinstance(data.get("mcpServers"), dict)
    )


class MCPConfigRule:
    """Flag dangerous shell, transport, and permission settings for MCP servers."""

    SHELL_COMMANDS = {"bash", "cmd", "cmd.exe", "powershell", "pwsh", "sh", "zsh"}

    def scan(self, path: Path, content: str) -> Iterable[Finding]:
        if path.suffix.lower() != ".json":
            return
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return
        if not _looks_like_mcp_config(path, data):
            return

        servers = data.get("mcpServers", data) if isinstance(data, dict) else {}
        if not isinstance(servers, dict):
            return
        for server_name, config in servers.items():
            if not isinstance(config, dict):
                continue
            yield from self._scan_server(path, content, str(server_name), config)

    def _scan_server(
        self, path: Path, content: str, server_name: str, config: Dict[str, Any]
    ) -> Iterable[Finding]:
        command = str(config.get("command", "")).lower()
        args = config.get("args", [])
        if command in self.SHELL_COMMANDS and isinstance(args, list) and any(
            str(arg).lower() in {"-c", "/c", "-command"} for arg in args
        ):
            line, column = line_containing(content, str(config.get("command", "")))
            yield Finding(
                "MCP001",
                "MCP server launched through a shell",
                Severity.HIGH,
                path,
                line,
                column,
                f"MCP server {server_name!r} executes a shell command string.",
                "Launch a fixed executable directly and pass each argument as a separate value.",
            )

        url = config.get("url")
        if isinstance(url, str) and self._is_insecure_remote_url(url):
            line, column = line_containing(content, url)
            yield Finding(
                "MCP002",
                "Unencrypted remote MCP transport",
                Severity.HIGH,
                path,
                line,
                column,
                f"MCP server {server_name!r} uses HTTP for a non-local endpoint.",
                "Use HTTPS and authenticate the remote MCP endpoint.",
            )

        allowed_tools = config.get("allowedTools", config.get("allowed_tools"))
        if allowed_tools == "*" or (
            isinstance(allowed_tools, list)
            and any(str(value).lower() in {"*", "all"} for value in allowed_tools)
        ):
            line, column = line_containing(content, "allowedTools")
            yield Finding(
                "MCP003",
                "Unrestricted MCP tool access",
                Severity.HIGH,
                path,
                line,
                column,
                f"MCP server {server_name!r} allows every tool.",
                "Grant only the specific MCP tools required by the application.",
            )

    @staticmethod
    def _is_insecure_remote_url(url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme.lower() != "http":
            return False
        return (parsed.hostname or "").lower() not in {"127.0.0.1", "localhost", "::1"}
