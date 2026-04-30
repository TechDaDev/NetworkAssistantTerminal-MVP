from pathlib import Path

from app.services.plugin_validator import validate_plugin_file


VALID_PLUGIN = '''
TOOL_NAME = "safe_reporter"
TOOL_VERSION = "0.1.0"
TOOL_DESCRIPTION = "Safe reporter."
TOOL_CATEGORY = "reporter"
TOOL_RISK_LEVEL = "low"
INPUT_SCHEMA = {}
OUTPUT_SCHEMA = {"success": "bool", "summary": "str", "data": "dict", "warnings": "list[str]"}
def run(inputs: dict) -> dict:
    return {"success": True, "summary": "ok", "data": {}, "warnings": []}
'''


def test_valid_plugin_passes_validation(tmp_path):
    path = tmp_path / "safe_reporter.py"
    path.write_text(VALID_PLUGIN, encoding="utf-8")

    result = validate_plugin_file(path)

    assert result.ok is True
    assert result.metadata["tool_name"] == "safe_reporter"


def test_missing_required_constants_fail_validation(tmp_path):
    path = tmp_path / "bad.py"
    path.write_text("def run(inputs: dict) -> dict:\n    return {}\n", encoding="utf-8")

    result = validate_plugin_file(path)

    assert result.ok is False
    assert "Missing required constants" in result.report


def test_missing_run_fails_validation(tmp_path):
    path = tmp_path / "bad.py"
    path.write_text(VALID_PLUGIN.replace("def run", "def nope"), encoding="utf-8")

    result = validate_plugin_file(path)

    assert result.ok is False
    assert "Missing required run" in result.report


def test_bad_run_signature_fails_validation(tmp_path):
    path = tmp_path / "bad.py"
    path.write_text(VALID_PLUGIN.replace("def run(inputs: dict) -> dict:", "def run(data: dict) -> dict:"), encoding="utf-8")

    result = validate_plugin_file(path)

    assert result.ok is False
    assert "inputs" in result.report


def test_forbidden_import_and_call_fail_validation(tmp_path):
    path = tmp_path / "bad.py"
    path.write_text(VALID_PLUGIN.replace("TOOL_NAME", "import subprocess\nTOOL_NAME").replace("return {", "open('x')\n    return {"), encoding="utf-8")

    result = validate_plugin_file(path)

    assert result.ok is False
    assert "subprocess" in result.report
    assert "open()" in result.report


def test_tool_name_validation(tmp_path):
    path = tmp_path / "bad.py"
    path.write_text(VALID_PLUGIN.replace('"safe_reporter"', '"Bad-Name"'), encoding="utf-8")

    result = validate_plugin_file(path)

    assert result.ok is False
    assert "TOOL_NAME" in result.report
