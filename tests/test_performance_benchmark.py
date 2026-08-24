import unittest

from benchmarks.performance import run_performance


class PerformanceBenchmarkTests(unittest.TestCase):
    def test_generated_project_corpus_reaches_terminal_sink(self):
        report = run_performance(20)

        self.assertEqual(report["errors"], 0)
        self.assertEqual(report["scanned_files"], 22)
        self.assertEqual(report["flow_findings"], 1)

    def test_rejects_empty_corpus(self):
        with self.assertRaisesRegex(ValueError, "positive"):
            run_performance(0)


if __name__ == "__main__":
    unittest.main()
