import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import Base, Device
from app.services import custom_plan_generator, plugin_registry, plugin_runner
from app.services.plugin_registry import approve_plugin, save_pending_plugin
from app.services.plugin_runner import run_plugin, save_planner_output_as_change_plan
from tests.test_plugin_validation import VALID_PLUGIN


PLANNER_PLUGIN = VALID_PLUGIN.replace('"safe_reporter"', '"route_planner"').replace('"reporter"', '"planner"').replace(
    'return {"success": True, "summary": "ok", "data": {}, "warnings": []}',
    'return {"success": True, "summary": "route", "data": {"platform": "cisco_ios", "target_device_ip": "192.168.88.20", "precheck_commands": ["show ip route"], "proposed_commands": ["ip route 10.1.0.0 255.255.255.0 192.168.88.1"], "rollback_commands": ["no ip route 10.1.0.0 255.255.255.0 192.168.88.1"], "verification_commands": ["show ip route"], "risk_summary": "route risk", "policy_summary": "backup"}, "warnings": []}'
)


def _install_temp_db(monkeypatch, tmp_path):
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    for module in (plugin_registry, custom_plan_generator):
        monkeypatch.setattr(module, "init_db", lambda: None)
        monkeypatch.setattr(module, "get_session", session_local)
    monkeypatch.setattr(plugin_registry, "PENDING_DIR", tmp_path / "pending")
    monkeypatch.setattr(plugin_registry, "APPROVED_DIR", tmp_path / "approved")
    monkeypatch.setattr(plugin_registry, "DISABLED_DIR", tmp_path / "disabled")
    return session_local


def test_pending_plugin_cannot_run(monkeypatch, tmp_path):
    _install_temp_db(monkeypatch, tmp_path)
    save_pending_plugin(tool_name="safe_reporter", version="0.1.0", description="safe", category="reporter", risk_level="low", code=VALID_PLUGIN)

    with pytest.raises(ValueError):
        run_plugin("safe_reporter", {})


def test_approved_plugin_can_run(monkeypatch, tmp_path):
    _install_temp_db(monkeypatch, tmp_path)
    save_pending_plugin(tool_name="safe_reporter", version="0.1.0", description="safe", category="reporter", risk_level="low", code=VALID_PLUGIN)
    approve_plugin("safe_reporter")

    result = run_plugin("safe_reporter", {})

    assert result.success is True


def test_invalid_output_schema_fails(monkeypatch, tmp_path):
    _install_temp_db(monkeypatch, tmp_path)
    bad = VALID_PLUGIN.replace('return {"success": True, "summary": "ok", "data": {}, "warnings": []}', 'return {"success": True}')
    save_pending_plugin(tool_name="safe_reporter", version="0.1.0", description="safe", category="reporter", risk_level="low", code=bad)
    approve_plugin("safe_reporter")

    with pytest.raises(ValueError):
        run_plugin("safe_reporter", {})


def test_planner_plugin_output_can_save_change_plan(monkeypatch, tmp_path):
    session_local = _install_temp_db(monkeypatch, tmp_path)
    with session_local() as session:
        session.add(Device(ip_address="192.168.88.20", vendor_guess="Cisco"))
        session.commit()
    save_pending_plugin(tool_name="route_planner", version="0.1.0", description="planner", category="planner", risk_level="medium", code=PLANNER_PLUGIN)
    approve_plugin("route_planner")

    result = run_plugin("route_planner", {})
    plan = save_planner_output_as_change_plan(result)

    assert plan.plan_type == "custom_cisco_plan"
