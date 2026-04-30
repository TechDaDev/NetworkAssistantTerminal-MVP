import pytest

from app.services.plugin_generator import PluginGenerationError, parse_plugin_json
from app.services.plugin_registry import save_pending_plugin

from tests.test_plugin_validation import VALID_PLUGIN


def test_valid_plugin_json_saves_to_pending(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.plugin_registry.PENDING_DIR", tmp_path / "pending")
    monkeypatch.setattr("app.services.plugin_registry.APPROVED_DIR", tmp_path / "approved")
    monkeypatch.setattr("app.services.plugin_registry.DISABLED_DIR", tmp_path / "disabled")
    draft = parse_plugin_json({
        "tool_name": "safe_reporter",
        "version": "0.1.0",
        "description": "Safe reporter.",
        "category": "reporter",
        "risk_level": "low",
        "input_schema": {},
        "code": VALID_PLUGIN,
    })

    assert draft.tool_name == "safe_reporter"


def test_invalid_json_is_rejected_safely():
    with pytest.raises(PluginGenerationError):
        parse_plugin_json("{not-json")
