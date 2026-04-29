from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.agent import agent_loop
from app.agent.agent_loop import process_agent_input
from app.agent.intent_parser import parse_intent
from app.agent.policy import evaluate_agent_action
from app.agent.session_memory import SessionMemory
from app.models import Base, ChangePlan, Device
from app.services import config_planner


def _install_temp_db(monkeypatch):
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    monkeypatch.setattr(config_planner, "init_db", lambda: None)
    monkeypatch.setattr(config_planner, "get_session", session_local)
    monkeypatch.setattr(config_planner, "_topology_findings_for_planned_commands", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(agent_loop, "log_agent_action", lambda **_kwargs: None)
    return session_local


def _add_device(session_local, ip: str, vendor: str = "Cisco") -> None:
    with session_local() as session:
        session.add(
            Device(
                ip_address=ip,
                vendor_guess=vendor,
                device_type_guess="Switch" if vendor == "Cisco" else "Router",
                confidence="High",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
        )
        session.commit()


def test_workflow_intents_parse():
    assert parse_intent("workflow scan and diagnose").tool_name == "workflow_scan_and_diagnose"
    assert parse_intent("start scan and diagnose").tool_name == "workflow_scan_and_diagnose"
    assert parse_intent("workflow topology report").tool_name == "workflow_topology_report"
    assert parse_intent("prepare cisco access port").tool_name == "workflow_prepare_cisco_access_port"
    assert parse_intent("prepare mikrotik dhcp").tool_name == "workflow_prepare_mikrotik_dhcp"


def test_workflow_policy_does_not_allow_high_risk_direct_execution():
    decision = evaluate_agent_action("workflow_scan_and_diagnose", {})
    assert decision.requires_confirmation
    assert decision.risk_level == "medium"
    blocked = evaluate_agent_action("execute_plan", {"plan_id": 1})
    assert not blocked.allowed


def test_prepare_cisco_access_port_workflow_creates_plan_only(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    _add_device(session_local, "192.168.88.20", "Cisco")

    result = process_agent_input(
        "prepare cisco access port device=192.168.88.20 interface=Gi0/5 vlan=30 description=LAB",
        SessionMemory(),
        session_id="test-session",
        confirm_fn=lambda *_args: True,
    )

    assert result.ok
    assert "PLAN ONLY" in result.message
    assert result.next_command.startswith("nat plan review")
    with session_local() as session:
        plan = session.get(ChangePlan, int(result.next_command.rsplit(" ", 1)[-1]))
        assert plan.status == "draft"
        assert plan.preflight_status == "not_run"


def test_prepare_mikrotik_dhcp_workflow_creates_plan_only(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    _add_device(session_local, "192.168.88.1", "MikroTik")

    result = process_agent_input(
        "prepare mikrotik dhcp device=192.168.88.1 name=lab-dhcp interface=bridge network=192.168.50.0/24 gateway=192.168.50.1 "
        "pool-name=lab-pool pool-range=192.168.50.100-192.168.50.150 dns=8.8.8.8 comment=LAB",
        SessionMemory(),
        session_id="test-session",
        confirm_fn=lambda *_args: True,
    )

    assert result.ok
    assert "PLAN ONLY" in result.message
    assert result.next_command.startswith("nat plan review")
    with session_local() as session:
        plan = session.get(ChangePlan, int(result.next_command.rsplit(" ", 1)[-1]))
        assert plan.status == "draft"
        assert plan.preflight_status == "not_run"
