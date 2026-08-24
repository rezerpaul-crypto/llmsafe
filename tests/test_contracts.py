import json
from pathlib import Path

from llmsafe.catalog import CATALOG_SCHEMA_VERSION
from llmsafe.cli import SCAN_SCHEMA_VERSION, render_json, render_rule_catalog
from llmsafe.sarif import SARIF_SCHEMA, to_sarif
from llmsafe.scanner import Scanner

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_scan_json_v1_has_the_documented_shape(tmp_path: Path) -> None:
    source = tmp_path / "unsafe.py"
    source.write_text("def run(model_output):\n    return eval(model_output)\n", encoding="utf-8")
    result = Scanner().scan([source])

    payload = json.loads(render_json(result))
    schema = json.loads(
        (PROJECT_ROOT / "docs/schemas/scan-v1.schema.json").read_text(encoding="utf-8")
    )

    assert payload["schema_version"] == SCAN_SCHEMA_VERSION == 1
    assert set(payload) == set(schema["required"])
    assert set(payload["summary"]) == set(schema["properties"]["summary"]["required"])
    assert set(payload["findings"][0]) == set(schema["$defs"]["finding"]["required"])
    assert set(payload["findings"][0]["evidence"][0]) == {
        "line",
        "column",
        "message",
    }


def test_catalog_json_v1_has_the_documented_shape() -> None:
    payload = json.loads(render_rule_catalog("json"))
    schema = json.loads(
        (PROJECT_ROOT / "docs/schemas/catalog-v1.schema.json").read_text(encoding="utf-8")
    )
    rule_schema = schema["properties"]["rules"]["items"]

    assert payload["schema_version"] == CATALOG_SCHEMA_VERSION == 1
    assert set(payload) == set(schema["required"])
    assert all(set(rule) == set(rule_schema["required"]) for rule in payload["rules"])
    assert [rule["id"] for rule in payload["rules"]] == sorted(
        rule["id"] for rule in payload["rules"]
    )


def test_sarif_contract_remains_21_and_deterministic(tmp_path: Path) -> None:
    source = tmp_path / "unsafe.py"
    source.write_text("exec(code)\n", encoding="utf-8")
    result = Scanner().scan([source])

    first = to_sarif(result)
    second = to_sarif(result)

    assert first == second
    assert first["$schema"] == SARIF_SCHEMA
    assert first["version"] == "2.1.0"
    assert first["runs"][0]["results"][0]["ruleId"] == "PY002"
    assert first["runs"][0]["invocations"][0]["executionSuccessful"] is True
