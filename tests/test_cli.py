import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from llmsafe.cli import main


class CLITests(unittest.TestCase):
    def run_cli(self, arguments):
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = main(arguments)
        return exit_code, output.getvalue()

    def test_clean_file_exits_zero(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "safe.py"
            path.write_text("print('hello')\n", encoding="utf-8")
            exit_code, output = self.run_cli([str(path)])

        self.assertEqual(exit_code, 0)
        self.assertIn("found 0 issue(s)", output)

    def test_high_finding_exits_one_and_json_is_machine_readable(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "unsafe.py"
            path.write_text("exec(model_output)\n", encoding="utf-8")
            exit_code, output = self.run_cli([str(path), "--format", "json"])

        payload = json.loads(output)
        self.assertEqual(exit_code, 1)
        self.assertEqual(payload["summary"]["findings"], 1)
        self.assertEqual(payload["findings"][0]["rule_id"], "PY002")

    def test_fail_threshold_can_be_raised(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "unsafe.py"
            path.write_text("eval(model_output)\n", encoding="utf-8")
            exit_code, _ = self.run_cli([str(path), "--fail-on", "critical"])

        self.assertEqual(exit_code, 0)

    def test_missing_path_exits_two(self):
        exit_code, output = self.run_cli(["not-a-real-file"])
        self.assertEqual(exit_code, 2)
        self.assertIn("Path does not exist", output)


if __name__ == "__main__":
    unittest.main()
