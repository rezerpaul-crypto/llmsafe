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


if __name__ == "__main__":
    unittest.main()
