import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import Base
from app.services import plugin_registry
from app.services.plugin_registry import approve_plugin, disable_plugin, register_approved_plugins_with_agent, save_pending_plugin
from tests.test_plugin_validation import VALID_PLUGIN


def _install_temp_db(monkeypatch, tmp_path):
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    monkeypatch.setattr(plugin_registry, "init_db", lambda: None)
    monkeypatch.setattr(plugin_registry, "get_session", session_local)
    monkeypatch.setattr(plugin_registry, "PENDING_DIR", tmp_path / "pending")
    monkeypatch.setattr(plugin_registry, "APPROVED_DIR", tmp_path / "approved")
    monkeypatch.setattr(plugin_registry, "DISABLED_DIR", tmp_path / "disabled")
    return session_local


def test_plugin_approve_requires_validation_passed(monkeypatch, tmp_path):
    _install_temp_db(monkeypatch, tmp_path)
    plugin = save_pending_plugin(tool_name="safe_reporter", version="0.1.0", description="safe", category="reporter", risk_level="low", code=VALID_PLUGIN)

    approved = approve_plugin(plugin.tool_name)

    assert approved.status == "approved"
    assert approved.validation_status == "passed"


def test_disable_removes_plugin_from_active_registry(monkeypatch, tmp_path):
    _install_temp_db(monkeypatch, tmp_path)
    plugin = save_pending_plugin(tool_name="safe_reporter", version="0.1.0", description="safe", category="reporter", risk_level="low", code=VALID_PLUGIN)
    approve_plugin(plugin.tool_name)
    disabled = disable_plugin(plugin.tool_name)

    assert disabled.status == "disabled"
    assert "safe_reporter" not in register_approved_plugins_with_agent()


def test_save_pending_rejects_unsafe_tool_name_before_write(monkeypatch, tmp_path):
    _install_temp_db(monkeypatch, tmp_path)

    with pytest.raises(ValueError):
        save_pending_plugin(tool_name="../bad", version="0.1.0", description="bad", category="reporter", risk_level="low", code=VALID_PLUGIN)

    assert not (tmp_path / "bad.py").exists()


def test_metadata_mismatch_fails_validation(monkeypatch, tmp_path):
    _install_temp_db(monkeypatch, tmp_path)

    plugin = save_pending_plugin(
        tool_name="safe_reporter",
        version="0.1.0",
        description="safe",
        category="reporter",
        risk_level="medium",
        code=VALID_PLUGIN,
    )

    assert plugin.validation_status == "failed"
    assert "TOOL_RISK_LEVEL" in plugin.validation_report
