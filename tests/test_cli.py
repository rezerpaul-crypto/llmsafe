import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from llmsafe.cli import SCAN_SCHEMA_VERSION, main


class CLITests(unittest.TestCase):
    def run_cli(self, arguments):
        output = io.StringIO()
        errors = io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            exit_code = main(arguments)
        return exit_code, output.getvalue(), errors.getvalue()

    def test_clean_file_exits_zero(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "safe.py"
            path.write_text("print('hello')\n", encoding="utf-8")
            exit_code, output, _ = self.run_cli([str(path)])

        self.assertEqual(exit_code, 0)
        self.assertIn("found 0 issue(s)", output)

    def test_high_finding_exits_one_and_json_is_machine_readable(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "unsafe.py"
            path.write_text("exec(model_output)\n", encoding="utf-8")
            exit_code, output, _ = self.run_cli([str(path), "--format", "json"])

        payload = json.loads(output)
        self.assertEqual(exit_code, 1)
        self.assertEqual(payload["schema_version"], SCAN_SCHEMA_VERSION)
        self.assertEqual(payload["summary"]["findings"], 1)
        self.assertEqual(payload["findings"][0]["rule_id"], "PY002")

    def test_fail_threshold_can_be_raised(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "unsafe.py"
            path.write_text("eval(model_output)\n", encoding="utf-8")
            exit_code, _, _ = self.run_cli([str(path), "--fail-on", "critical"])

        self.assertEqual(exit_code, 0)

    def test_missing_path_exits_two(self):
        exit_code, output, _ = self.run_cli(["not-a-real-file"])
        self.assertEqual(exit_code, 2)
        self.assertIn("Path does not exist", output)

    def test_baseline_allows_incremental_adoption_and_reports_new_findings(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "agent.py"
            baseline = root / ".llmsafe-baseline.json"
            source.write_text("eval(existing)\n", encoding="utf-8")

            write_exit, _, message = self.run_cli(
                [str(source), "--write-baseline", str(baseline)]
            )
            clean_exit, clean_output, _ = self.run_cli(
                [str(source), "--baseline", str(baseline)]
            )
            source.write_text("eval(existing)\nexec(new_issue)\n", encoding="utf-8")
            new_exit, new_output, _ = self.run_cli(
                [str(source), "--baseline", str(baseline)]
            )

        self.assertEqual(write_exit, 0)
        self.assertIn("Wrote 1 finding(s)", message)
        self.assertEqual(clean_exit, 0)
        self.assertIn("Ignored 1 baseline finding(s)", clean_output)
        self.assertEqual(new_exit, 1)
        self.assertIn("PY002", new_output)
        self.assertNotIn("PY001", new_output)

    def test_invalid_baseline_exits_two_without_scanning(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            baseline = Path(temporary_directory) / "invalid.json"
            baseline.write_text("not json", encoding="utf-8")
            exit_code, output, errors = self.run_cli([".", "--baseline", str(baseline)])

        self.assertEqual(exit_code, 2)
        self.assertEqual(output, "")
        self.assertIn("baseline error", errors)

    def test_output_and_baseline_destinations_must_differ(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination = Path(temporary_directory) / "result.json"
            exit_code, _, errors = self.run_cli(
                [".", "--output", str(destination), "--write-baseline", str(destination)]
            )

        self.assertEqual(exit_code, 2)
        self.assertIn("must differ", errors)


if __name__ == "__main__":
    unittest.main()
