import json
import tempfile
import unittest
from pathlib import Path

from llmsafe.catalog import RULES_BY_ID
from llmsafe.cli import main
from llmsafe.sarif import SARIF_SCHEMA, to_sarif
from llmsafe.scanner import Scanner


class SarifTests(unittest.TestCase):
    def test_renders_rule_location_evidence_and_fingerprint(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "agent.py"
            path.write_text(
                "def run(model_output):\n    return eval(model_output)\n", encoding="utf-8"
            )
            result = Scanner().scan([path])

        sarif = to_sarif(result)
        run = sarif["runs"][0]
        flow_result = next(item for item in run["results"] if item["ruleId"] == "FLOW001")
        self.assertEqual(sarif["$schema"], SARIF_SCHEMA)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(flow_result["level"], "error")
        self.assertIn("primaryLocationLineHash", flow_result["partialFingerprints"])
        self.assertGreaterEqual(len(flow_result["relatedLocations"]), 2)
        flow_rule = next(item for item in run["tool"]["driver"]["rules"] if item["id"] == "FLOW001")
        self.assertEqual(
            flow_rule["fullDescription"]["text"], RULES_BY_ID["FLOW001"].description
        )
        self.assertIn("dataflow", flow_rule["properties"]["tags"])

    def test_cli_writes_valid_sarif_file(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "unsafe.py"
            output = root / "reports" / "llmsafe.sarif"
            source.write_text("exec(code)\n", encoding="utf-8")

            exit_code = main([str(source), "--format", "sarif", "--output", str(output)])
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 1)
        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(payload["runs"][0]["results"][0]["ruleId"], "PY002")

    def test_cross_file_evidence_uses_related_artifact(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "helpers.py").write_text(
                "def evaluate(value):\n    return eval(value)\n",
                encoding="utf-8",
            )
            (root / "app.py").write_text(
                "from helpers import evaluate\n\n"
                "def handle(user_input):\n"
                "    return evaluate(user_input)\n",
                encoding="utf-8",
            )
            result = Scanner().scan([root])
            sarif = to_sarif(result)

        flow_result = next(
            item for item in sarif["runs"][0]["results"] if item["ruleId"] == "FLOW001"
        )
        related_uris = {
            item["physicalLocation"]["artifactLocation"]["uri"]
            for item in flow_result["relatedLocations"]
        }
        self.assertTrue(any(uri.endswith("helpers.py") for uri in related_uris))

    def test_policy_can_disable_a_rule_and_raise_threshold(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "unsafe.py"
            policy = root / ".llmsafe.toml"
            source.write_text("eval(data)\n", encoding="utf-8")
            policy.write_text(
                '[llmsafe]\ndisabled_rules = ["PY001"]\nfail_on = "critical"\n',
                encoding="utf-8",
            )

            exit_code = main([str(source), "--config", str(policy)])

        self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
