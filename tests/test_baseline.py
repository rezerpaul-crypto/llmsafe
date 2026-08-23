import json
import tempfile
import unittest
from pathlib import Path

from llmsafe.baseline import (
    BaselineError,
    apply_baseline,
    finding_fingerprint,
    load_baseline,
    write_baseline,
)
from llmsafe.scanner import Scanner


class BaselineTests(unittest.TestCase):
    def test_round_trip_hides_only_recorded_number_of_findings(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "agent.py"
            baseline_path = root / ".llmsafe-baseline.json"
            source.write_text("eval(first)\neval(second)\n", encoding="utf-8")
            original = Scanner().scan([source])

            count = write_baseline(baseline_path, original.findings, root)
            baseline = load_baseline(baseline_path)
            source.write_text("eval(first)\neval(second)\neval(third)\n", encoding="utf-8")
            updated = Scanner().scan([source])
            filtered = apply_baseline(updated, baseline, root)

        self.assertEqual(count, 2)
        self.assertEqual(filtered.baseline_findings, 2)
        self.assertEqual([finding.rule_id for finding in filtered.findings], ["PY001"])

    def test_fingerprint_survives_line_movement(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "agent.py"
            source.write_text("eval(data)\n", encoding="utf-8")
            before = Scanner().scan([source]).findings[0]
            source.write_text("\n\n# moved\neval(data)\n", encoding="utf-8")
            after = Scanner().scan([source]).findings[0]

        self.assertEqual(finding_fingerprint(before, root), finding_fingerprint(after, root))

    def test_writer_is_deterministic_and_uses_relative_paths(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "src" / "agent.py"
            source.parent.mkdir()
            source.write_text("exec(code)\n", encoding="utf-8")
            findings = Scanner().scan([source]).findings
            first = root / "first.json"
            second = root / "second.json"

            write_baseline(first, findings, root)
            write_baseline(second, findings, root)
            first_content = first.read_text(encoding="utf-8")
            second_content = second.read_text(encoding="utf-8")
            payload = json.loads(first_content)

        self.assertEqual(first_content, second_content)
        self.assertEqual(payload["findings"][0]["path"], "src/agent.py")

    def test_rejects_invalid_schema_and_fingerprint(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "baseline.json"
            path.write_text('{"schema_version": 2, "findings": []}', encoding="utf-8")
            with self.assertRaisesRegex(BaselineError, "schema_version 1"):
                load_baseline(path)

            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "findings": [
                            {"fingerprint": "bad", "line": 1, "path": "a.py", "rule_id": "X"}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(BaselineError, "SHA-256"):
                load_baseline(path)


if __name__ == "__main__":
    unittest.main()
