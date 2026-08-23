import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from llmsafe.catalog import CATALOG_SCHEMA_VERSION, RULE_CATALOG, RULES_BY_ID
from llmsafe.cli import main
from llmsafe.scanner import Scanner


class CatalogTests(unittest.TestCase):
    def test_catalog_is_unique_complete_and_matches_emitted_findings(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            provider_key = "sk-" + "a" * 24
            aws_key = "AKIA" + "B" * 16
            github_token = "ghp_" + "c" * 36
            (root / "agent.py").write_text(
                f'''import os
import pickle
import requests
import subprocess
import yaml

openai_key = "{provider_key}"
aws_key = "{aws_key}"
github_token = "{github_token}"
private_key = "-----BEGIN PRIVATE KEY-----"
password = "production-password"

def run(user_input, model_output, blob, document, tools, cursor):
    system_prompt = f"Follow {{user_input}}"
    eval(user_input)
    exec(model_output)
    os.system(user_input)
    subprocess.run(model_output, shell=True)
    cursor.execute(user_input)
    requests.get(user_input)
    tools[user_input]()
    pickle.loads(blob)
    yaml.load(document)
    PythonREPLTool()
    Agent(allow_dangerous_code=True)
    Agent(require_approval=False)
''',
                encoding="utf-8",
            )
            (root / "mcp.json").write_text(
                '''{
  "mcpServers": {
    "unsafe": {
      "command": "sh",
      "args": ["-c", "run"],
      "url": "http://tools.example.org/mcp",
      "allowedTools": "*"
    }
  }
}
''',
                encoding="utf-8",
            )

            findings = Scanner().scan([root]).findings

        catalog_ids = {rule.rule_id for rule in RULE_CATALOG}
        self.assertEqual(len(catalog_ids), len(RULE_CATALOG))
        self.assertEqual({finding.rule_id for finding in findings}, catalog_ids)
        for finding in findings:
            metadata = RULES_BY_ID[finding.rule_id]
            self.assertEqual(finding.title, metadata.title)
            self.assertEqual(finding.severity, metadata.severity)

    def test_json_catalog_is_stable_and_does_not_scan_paths(self):
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = main(["missing-path", "--list-rules", "--format", "json"])
        payload = json.loads(output.getvalue())

        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["schema_version"], CATALOG_SCHEMA_VERSION)
        self.assertEqual(len(payload["rules"]), len(RULE_CATALOG))
        self.assertEqual(
            [rule["id"] for rule in payload["rules"]],
            sorted(rule.rule_id for rule in RULE_CATALOG),
        )

    def test_sarif_is_rejected_for_catalog_output(self):
        errors = io.StringIO()
        with redirect_stderr(errors):
            exit_code = main(["--list-rules", "--format", "sarif"])

        self.assertEqual(exit_code, 2)
        self.assertIn("supports text or json", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
