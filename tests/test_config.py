import tempfile
import unittest
from pathlib import Path

from llmsafe.config import ConfigError, discover_config, load_config
from llmsafe.models import Severity


class ConfigTests(unittest.TestCase):
    def test_loads_dedicated_policy(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / ".llmsafe.toml"
            path.write_text(
                """[llmsafe]
exclude = ["generated/**", "vendor"]
fail_on = "medium"
max_file_size = 2048
disabled_rules = ["py001", "FLOW004"]
""",
                encoding="utf-8",
            )

            config = load_config(path)

        self.assertEqual(config.excludes, ("generated/**", "vendor"))
        self.assertEqual(config.fail_on, Severity.MEDIUM)
        self.assertEqual(config.max_file_size, 2048)
        self.assertEqual(config.disabled_rules, frozenset({"PY001", "FLOW004"}))

    def test_discovers_pyproject_policy_from_child_directory(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            child = root / "src" / "package"
            child.mkdir(parents=True)
            pyproject = root / "pyproject.toml"
            pyproject.write_text('[tool.llmsafe]\nfail_on = "critical"\n', encoding="utf-8")

            selected = discover_config(child)
            config = load_config(start=child)

        self.assertEqual(selected, pyproject.resolve())
        self.assertEqual(config.fail_on, Severity.CRITICAL)

    def test_rejects_unknown_setting(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / ".llmsafe.toml"
            path.write_text('[llmsafe]\nmagic = true\n', encoding="utf-8")
            with self.assertRaisesRegex(ConfigError, "Unknown setting"):
                load_config(path)

    def test_rejects_invalid_types_and_missing_file(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            invalid = root / "invalid.toml"
            invalid.write_text('[llmsafe]\nmax_file_size = false\n', encoding="utf-8")
            with self.assertRaisesRegex(ConfigError, "positive integer"):
                load_config(invalid)
            with self.assertRaisesRegex(ConfigError, "does not exist"):
                load_config(root / "missing.toml")


if __name__ == "__main__":
    unittest.main()
