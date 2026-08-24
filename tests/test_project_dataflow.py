import tempfile
import unittest
from pathlib import Path
from typing import Dict

from llmsafe.scanner import Scanner


class ProjectDataflowTests(unittest.TestCase):
    def scan(self, sources: Dict[str, str], target: str = "."):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for relative_path, content in sources.items():
                path = root / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            result = Scanner().scan([root / target])
        return [finding for finding in result.findings if finding.rule_id.startswith("FLOW")]

    def test_resolves_relative_import_alias_and_cross_file_evidence(self):
        findings = self.scan(
            {
                "pkg/__init__.py": "",
                "pkg/helpers.py": "def evaluate(value):\n    return eval(value)\n",
                "pkg/app.py": (
                    "from .helpers import evaluate as run_expression\n\n"
                    "def handle(user_input):\n"
                    "    return run_expression(user_input)\n"
                ),
            },
            target="pkg",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])
        sink = next(step for step in findings[0].evidence if "helper reaches" in step.message)
        self.assertIsNotNone(sink.path)
        self.assertEqual(sink.path.name, "helpers.py")
        self.assertTrue(sink.to_dict()["path"].endswith("pkg/helpers.py"))

    def test_resolves_module_alias_and_keyword_argument(self):
        findings = self.scan(
            {
                "pkg/__init__.py": "",
                "pkg/helpers.py": (
                    "def launch(*, value):\n"
                    "    import os\n"
                    "    return os.system(value)\n"
                ),
                "app.py": (
                    "import pkg.helpers as operations\n\n"
                    "def handle(user_input):\n"
                    "    return operations.launch(value=user_input)\n"
                ),
            }
        )

        self.assertEqual([finding.rule_id for finding in findings], ["FLOW002"])

    def test_resolves_unaliased_module_import(self):
        findings = self.scan(
            {
                "pkg/__init__.py": "",
                "pkg/helpers.py": "def evaluate(value):\n    return eval(value)\n",
                "app.py": (
                    "import pkg.helpers\n\n"
                    "def handle(user_input):\n"
                    "    return pkg.helpers.evaluate(user_input)\n"
                ),
            }
        )

        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])

    def test_follows_reexport(self):
        findings = self.scan(
            {
                "pkg/__init__.py": "from .helpers import evaluate\n",
                "pkg/helpers.py": "def evaluate(value):\n    return eval(value)\n",
                "app.py": (
                    "from pkg import evaluate\n\n"
                    "def handle(user_input):\n"
                    "    return evaluate(user_input)\n"
                ),
            }
        )

        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])

    def test_converges_through_import_cycle(self):
        findings = self.scan(
            {
                "pkg/__init__.py": "",
                "pkg/a.py": (
                    "from .b import forward\n\n"
                    "def start(value):\n"
                    "    return forward(value)\n"
                ),
                "pkg/b.py": (
                    "from .a import start\n\n"
                    "def forward(value):\n"
                    "    return eval(value)\n"
                ),
                "app.py": (
                    "from pkg.a import start\n\n"
                    "def handle(user_input):\n"
                    "    return start(user_input)\n"
                ),
            }
        )

        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])

    def test_fixed_argument_to_imported_sink_is_safe(self):
        findings = self.scan(
            {
                "helpers.py": "def evaluate(value):\n    return eval(value)\n",
                "app.py": "from helpers import evaluate\n\nevaluate('2 + 2')\n",
            }
        )

        self.assertEqual(findings, [])

    def test_does_not_guess_external_imports(self):
        findings = self.scan(
            {
                "app.py": (
                    "from unavailable_dependency import evaluate\n\n"
                    "def handle(user_input):\n"
                    "    return evaluate(user_input)\n"
                )
            }
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
