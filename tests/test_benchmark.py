import unittest
from pathlib import Path

from benchmarks.run import run_benchmark


class BenchmarkTests(unittest.TestCase):
    def test_checked_in_benchmark_matches_expectations(self):
        root = Path(__file__).parents[1] / "benchmarks"
        report = run_benchmark(root)

        self.assertEqual(report["summary"]["passed"], report["summary"]["cases"])
        self.assertEqual(report["summary"]["rule_recall"], 1.0)
        self.assertGreaterEqual(report["summary"]["expected_findings"], 10)

    def test_public_benchmark_counts_match_manifest(self):
        project_root = Path(__file__).parents[1]
        report = run_benchmark(project_root / "benchmarks")
        summary = report["summary"]
        documentation = (project_root / "docs" / "benchmark.md").read_text(encoding="utf-8")
        readme = (project_root / "README.md").read_text(encoding="utf-8")

        self.assertIn(
            f"Cases: {summary['passed']}/{summary['cases']} passing",
            documentation,
        )
        self.assertIn(
            f"Expected rule signals: {summary['expected_findings']}",
            documentation,
        )
        self.assertIn(
            f"Detected expected rule signals: {summary['detected_findings']}",
            documentation,
        )
        self.assertIn(
            f"expects {summary['expected_findings']} rule-level signals",
            readme,
        )


if __name__ == "__main__":
    unittest.main()
