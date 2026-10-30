import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from llmsafe.cli import main
from llmsafe.rules.eval import DangerousPythonRule
from llmsafe.rules.mcp import MCPConfigRule
from llmsafe.rules.prompts import DynamicSystemPromptRule
from llmsafe.rules.secrets import SecretRule
from llmsafe.rules.shell import ShellExecutionRule

SYNTHETIC_SECRET_MARKERS = (
    "api_key_123",
    "bearer_token",
    "ghp_test_token",
    "test-client-secret",
    "test-key",
    "test_api_key",
    "test_client_secret",
)


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
        content = (
            'api_key = "your-api-key-here"\n'
            'password = "change-me-now"\n'
            'api_key = "api_key_123"\n'
            'api_key = "test-key"\n'
            'api_key = "test_api_key"\n'
            'api_key = "TEST_API_KEY"\n'
            'api_key = "ghp_test_token"\n'
            'client_secret = "test-client-secret"\n'
            'client_secret = "test_client_secret"\n'
            'access_token = "bearer_token"\n'
            'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'
        )
        self.assertEqual(list(SecretRule().scan(Path("settings.py"), content)), [])

    def test_placeholder_suppression_is_exact(self):
        near_generic_placeholder = "test-key-" + "production-value"
        near_aws_example = "AKIA" + "IOSFODNN7EXAMPLF"
        content = (
            f'api_key = "{near_generic_placeholder}"\n'
            f'AWS_ACCESS_KEY_ID = "{near_aws_example}"\n'
        )

        findings = list(SecretRule().scan(Path("settings.py"), content))

        self.assertEqual([item.rule_id for item in findings], ["SECRET002", "SECRET005"])

    def test_provider_example_is_ignored_with_standalone_delimiters(self):
        example = "AKIA" + "IOSFODNN7EXAMPLE"
        templates = (
            "{key}",
            "{key}\n",
            "\t{key}\r\n",
            'identifier = "{key}"',
            "identifier = '{key}'",
            "AWS_ACCESS_KEY_ID={key}",
            "AWS_ACCESS_KEY_ID: {key}",
            "AWS_ACCESS_KEY_ID:{key}",
            '{{"identifier": "{key}"}}',
            "[{key}];",
            "{{{key}}}",
            "first,{key},next",
            "The documented identifier is `{key}`.",
            "({key}), another value",
        )

        for template in templates:
            with self.subTest(template=template):
                content = template.format(key=example)
                findings = list(SecretRule().scan(Path("settings.txt"), content))
                self.assertEqual(findings, [])

    def test_provider_example_embedded_in_longer_token_is_reported(self):
        example = "AKIA" + "IOSFODNN7EXAMPLE"
        values = (
            "prefix-" + example,
            example + "-suffix",
            "prefix/" + example,
            example + "/suffix",
            "prefix+" + example,
            example + "+suffix",
            "prefix." + example,
            example + ".suffix",
            "prefix\\" + example,
            example + "\\suffix",
            "prefix%" + example,
            example + "%2Fsuffix",
            "prefix@" + example,
            example + "@suffix",
            "prefix!" + example,
            example + "!suffix",
            example + "=suffix",
            example + ":suffix",
            "prefix\u200b" + example,
            example + "\u200bsuffix",
        )

        for filename in ("src/settings.py", "tests/fixture.py"):
            for value in values:
                with self.subTest(filename=filename, value=value):
                    content = f'identifier = "{value}"'
                    findings = list(SecretRule().scan(Path(filename), content))
                    self.assertEqual([item.rule_id for item in findings], ["SECRET002"])
                    self.assertNotIn(value, findings[0].message)

    def test_generic_markers_are_case_insensitive_in_all_credential_variables(self):
        for filename in ("src/settings.py", "tests/fixture.py"):
            for variable in ("api_key", "client_secret", "password", "access_token"):
                for marker in SYNTHETIC_SECRET_MARKERS:
                    for value in (marker, marker.upper(), marker.title()):
                        with self.subTest(filename=filename, variable=variable, value=value):
                            content = f'{variable} = "{value}"'
                            self.assertEqual(list(SecretRule().scan(Path(filename), content)), [])

    def test_generic_placeholder_near_matches_remain_findings(self):
        for filename in ("src/settings.py", "tests/fixture.py"):
            for variable in ("api_key", "client_secret", "password", "access_token"):
                for value in SYNTHETIC_SECRET_MARKERS:
                    for near_match in ("prefix-" + value, value + "-suffix", value[:-1] + "x"):
                        with self.subTest(filename=filename, variable=variable, value=near_match):
                            content = f'{variable} = "{near_match}"'
                            findings = list(SecretRule().scan(Path(filename), content))
                            self.assertEqual([item.rule_id for item in findings], ["SECRET005"])

    def test_provider_example_does_not_hide_other_secrets_in_the_same_file(self):
        example = "AKIA" + "IOSFODNN7EXAMPLE"
        values = (
            "sk-" + "a" * 24,
            "AKIA" + "B" * 16,
            "ASIA" + "C" * 16,
            example[:-1] + "F",
            "ghp_" + "d" * 36,
            "-----BEGIN " + "PRIVATE KEY-----",
        )
        content = f'identifier = "{example}"\n'
        content += "\n".join(f'identifier = "{value}"' for value in values)
        credential_value = "production-" + "password"
        content += "\npass" + f'word = "{credential_value}"\n'

        for filename in ("src/settings.py", "tests/fixture.py"):
            with self.subTest(filename=filename):
                findings = list(SecretRule().scan(Path(filename), content))
                self.assertEqual(
                    [item.rule_id for item in findings],
                    [
                        "SECRET001", "SECRET002", "SECRET002", "SECRET002",
                        "SECRET003", "SECRET004", "SECRET005",
                    ],
                )
                self.assertTrue(all(item.line > 1 for item in findings))

    def test_cli_preserves_compound_findings_and_exit_codes(self):
        example = "AKIA" + "IOSFODNN7EXAMPLE"
        values = (example, "prefix\\" + example, example + "%2Fsuffix", example + "@suffix")
        with tempfile.TemporaryDirectory() as temporary_directory:
            for filename in ("src/settings.env", "tests/fixture.env"):
                path = Path(temporary_directory) / filename
                path.parent.mkdir(parents=True, exist_ok=True)
                for value in values:
                    with self.subTest(filename=filename, value=value):
                        path.write_text(f'identifier = "{value}"\n', encoding="utf-8")
                        output = io.StringIO()
                        with redirect_stdout(output):
                            exit_code = main([str(path), "--format", "json", "--fail-on", "high"])
                        payload = json.loads(output.getvalue())
                        self.assertEqual(payload["errors"], [])
                        expected_rules = [] if value == example else ["SECRET002"]
                        self.assertEqual(
                            [item["rule_id"] for item in payload["findings"]], expected_rules
                        )
                        self.assertEqual(exit_code, 0 if value == example else 1)
                        self.assertNotIn(value, output.getvalue())


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
