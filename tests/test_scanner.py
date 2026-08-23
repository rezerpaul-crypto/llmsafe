import tempfile
import unittest
from pathlib import Path

from llmsafe.models import Severity
from llmsafe.scanner import Scanner


class ScannerTests(unittest.TestCase):
    def test_scans_directory_and_sorts_by_severity(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            provider_key = "sk-" + "x" * 24
            (root / "agent.py").write_text(
                f'key = "{provider_key}"\neval(payload)\n', encoding="utf-8"
            )

            result = Scanner().scan([root])

        self.assertEqual(result.scanned_files, 1)
        self.assertEqual([item.rule_id for item in result.findings], ["SECRET001", "PY001"])
        self.assertTrue(result.has_findings_at(Severity.CRITICAL))

    def test_inline_rule_suppression_is_scoped(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "agent.py"
            path.write_text(
                "# llmsafe: ignore[PY001]\neval(trusted_expression)\nexec(code)\n",
                encoding="utf-8",
            )

            result = Scanner().scan([path])

        self.assertEqual([item.rule_id for item in result.findings], ["PY002"])

    def test_excludes_matching_paths(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            generated = root / "generated"
            generated.mkdir()
            (generated / "unsafe.py").write_text("exec(code)\n", encoding="utf-8")
            (root / "safe.py").write_text("print('safe')\n", encoding="utf-8")

            result = Scanner(excludes=["generated"]).scan([root])

        self.assertEqual(result.scanned_files, 1)
        self.assertEqual(result.findings, ())

    def test_missing_target_is_reported_as_error(self):
        result = Scanner().scan([Path("definitely-does-not-exist")])
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(result.scanned_files, 0)

    def test_binary_and_large_files_are_skipped(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "binary.txt").write_bytes(b"text\x00more")
            (root / "large.txt").write_text("x" * 50, encoding="utf-8")

            result = Scanner(max_file_size=10).scan([root])

        self.assertEqual(result.skipped_files, 2)
        self.assertEqual(result.scanned_files, 0)


if __name__ == "__main__":
    unittest.main()
