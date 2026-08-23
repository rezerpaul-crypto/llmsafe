import unittest
from pathlib import Path

from llmsafe.rules.eval import DangerousPythonRule
from llmsafe.rules.mcp import MCPConfigRule
from llmsafe.rules.prompts import DynamicSystemPromptRule
from llmsafe.rules.secrets import SecretRule
from llmsafe.rules.shell import ShellExecutionRule


def rule_ids(rule, filename, content):
    return {finding.rule_id for finding in rule.scan(Path(filename), content)}


class SecretRuleTests(unittest.TestCase):
    def test_detects_provider_and_generic_secrets(self):
        provider_key = "sk-" + "a" * 24
        content = f'OPENAI_API_KEY = "{provider_key}"\npassword = "a-real-password"\n'

        findings = list(SecretRule().scan(Path("agent.py"), content))

        self.assertEqual({item.rule_id for item in findings}, {"SECRET001", "SECRET005"})
        self.assertEqual(findings[0].line, 1)

    def test_ignores_explicit_placeholders(self):
        content = 'api_key = "your-api-key-here"\npassword = "change-me-now"\n'
        self.assertEqual(list(SecretRule().scan(Path("settings.py"), content)), [])


class PythonRuleTests(unittest.TestCase):
    def test_detects_dynamic_execution_and_unsafe_deserialization(self):
        content = "import pickle\neval(payload)\nexec(code)\npickle.loads(blob)\n"
        self.assertEqual(
            rule_ids(DangerousPythonRule(), "agent.py", content),
            {"PY001", "PY002", "PY003"},
        )

    def test_does_not_scan_non_python_as_python(self):
        self.assertEqual(rule_ids(DangerousPythonRule(), "notes.md", "eval(payload)"), set())

    def test_detects_shell_apis(self):
        content = (
            "import os\nimport subprocess\n"
            "os.system(command)\nsubprocess.run(command, shell=True)\n"
        )
        self.assertEqual(
            rule_ids(ShellExecutionRule(), "tools.py", content),
            {"SHELL001", "SHELL002"},
        )

    def test_allows_subprocess_argument_list(self):
        content = 'import subprocess\nsubprocess.run(["git", "status"], check=True)\n'
        self.assertEqual(rule_ids(ShellExecutionRule(), "tools.py", content), set())


class PromptRuleTests(unittest.TestCase):
    def test_detects_dynamic_system_prompt(self):
        content = 'system_prompt = f"You are helpful. User data: {user_input}"\n'
        self.assertEqual(
            rule_ids(DynamicSystemPromptRule(), "agent.py", content),
            {"LLM001"},
        )

    def test_allows_static_system_prompt(self):
        content = 'system_prompt = "You are a careful assistant."\n'
        self.assertEqual(rule_ids(DynamicSystemPromptRule(), "agent.py", content), set())


class MCPRuleTests(unittest.TestCase):
    def test_detects_shell_http_and_wildcard_tools(self):
        content = """{
          "mcpServers": {
            "unsafe": {
              "command": "sh",
              "args": ["-c", "download-and-run"],
              "url": "http://tools.example.org/mcp",
              "allowedTools": ["*"]
            }
          }
        }"""
        self.assertEqual(
            rule_ids(MCPConfigRule(), "mcp.json", content),
            {"MCP001", "MCP002", "MCP003"},
        )

    def test_allows_local_http_endpoint(self):
        content = '{"mcpServers": {"local": {"url": "http://localhost:8080/mcp"}}}'
        self.assertEqual(rule_ids(MCPConfigRule(), "mcp.json", content), set())

    def test_ignores_unrelated_json(self):
        content = '{"url": "http://tools.example.org"}'
        self.assertEqual(rule_ids(MCPConfigRule(), "package.json", content), set())


if __name__ == "__main__":
    unittest.main()
