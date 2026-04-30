from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import Base, Device
from app.services import custom_plan_generator
from app.services.custom_plan_generator import parse_custom_plan_json, save_custom_plan


ROUTEROS_PLAN = {
    "plan_type": "custom_routeros_plan",
    "target_device_ip": "192.168.88.1",
    "platform": "mikrotik_routeros",
    "task_summary": "Add lab NAT rule",
    "policy_summary": "Backup and confirmation required.",
    "risk_summary": "NAT changes may affect traffic.",
    "missing_inputs": [],
    "precheck_commands": ["/ip firewall nat print"],
    "proposed_commands": ["/ip firewall nat add chain=srcnat src-address=192.168.50.0/24 action=masquerade comment=\"NA-PLAN-1\""],
    "rollback_commands": ["/ip firewall nat remove [find comment=\"NA-PLAN-1\"]"],
    "verification_commands": ["/ip firewall nat print"],
    "warnings": ["Confirm lab subnet."],
}


def _install_temp_db(monkeypatch):
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    monkeypatch.setattr(custom_plan_generator, "init_db", lambda: None)
    monkeypatch.setattr(custom_plan_generator, "get_session", session_local)
    return session_local


def test_deepseek_routeros_json_plan_parses():
    draft = parse_custom_plan_json(ROUTEROS_PLAN)

    assert draft.plan_type == "custom_routeros_plan"
    assert draft.platform == "mikrotik_routeros"
    assert draft.proposed_commands


def test_missing_inputs_are_detected():
    draft = parse_custom_plan_json({**ROUTEROS_PLAN, "target_device_ip": None, "missing_inputs": ["Target router IP"], "proposed_commands": [], "rollback_commands": [], "verification_commands": []})

    assert draft.has_missing_inputs is True
    assert draft.missing_inputs == ["Target router IP"]


def test_custom_plan_saves_as_high_risk(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    with session_local() as session:
        session.add(Device(ip_address="192.168.88.1", vendor_guess="MikroTik", device_type_guess="Router"))
        session.commit()

    plan = save_custom_plan(parse_custom_plan_json(ROUTEROS_PLAN))

    assert plan.plan_type == "custom_routeros_plan"
    assert plan.risk_level == "high"
    assert plan.status == "draft"
    assert "deepseek" in plan.custom_plan_metadata_json
