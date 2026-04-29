from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import Base, ChangePlan, CommandRun, Device, DeviceCredential
from app.services import config_executor, config_planner
from app.services.config_planner import run_preflight


def _install_temp_db(monkeypatch):
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    monkeypatch.setattr(config_planner, "init_db", lambda: None)
    monkeypatch.setattr(config_planner, "get_session", session_local)
    monkeypatch.setattr(config_executor, "init_db", lambda: None)
    monkeypatch.setattr(config_executor, "get_session", session_local)
    return session_local


def _add_plan(session_local, *, plan_type="cisco_access_port", status="approved", evidence=True, trunk=False, vlan_present=True, credentials=True):
    now = datetime.now(timezone.utc)
    with session_local() as session:
        device = Device(ip_address="192.168.88.20", vendor_guess="Cisco", device_type_guess="Switch", confidence="High")
        if credentials:
            device.credentials = [
                DeviceCredential(username="admin", encrypted_password="encrypted", connection_type="ssh", platform_hint="cisco_ios")
            ]
        if evidence:
            device.command_runs = [
                CommandRun(command="show interfaces status", output="Gi0/5 connected 30 a-full a-100", success=True, started_at=now, finished_at=now),
                CommandRun(command="show interfaces trunk", output="Gi0/5 trunking" if trunk else "", success=True, started_at=now, finished_at=now),
                CommandRun(command="show vlan brief", output="30 LAB active" if vlan_present else "1 default active", success=True, started_at=now, finished_at=now),
            ]
        if plan_type == "cisco_interface_description":
            proposed = "interface Gi0/5\n description LAB-PC-01"
            rollback = "interface Gi0/5\n no description"
        else:
            proposed = "interface Gi0/5\n switchport mode access\n switchport access vlan 30\n spanning-tree portfast\n description LAB-PC-01"
            rollback = "interface Gi0/5\n no switchport access vlan 30\n no spanning-tree portfast\n no description"
        plan = ChangePlan(
            device=device,
            plan_type=plan_type,
            title="test",
            description="test",
            risk_level="medium",
            status=status,
            proposed_commands=proposed,
            rollback_commands=rollback,
            validation_findings="[]",
        )
        session.add(plan)
        session.commit()
        return plan.id


def test_non_approved_interface_plan_preflight_fails(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local, status="draft")

    result = run_preflight(plan_id)

    assert result.plan.preflight_status == "failed"
    assert any(finding.title == "Plan is not approved" for finding in result.findings)


def test_missing_evidence_returns_warning(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local, evidence=False)

    result = run_preflight(plan_id)

    assert result.plan.preflight_status == "warning"
    assert any(finding.title == "Interface evidence missing" for finding in result.findings)


def test_stored_evidence_allows_passed_preflight(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local)

    result = run_preflight(plan_id)

    assert result.plan.preflight_status == "passed"


def test_trunk_conflict_fails_preflight(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local, trunk=True)

    result = run_preflight(plan_id)

    assert result.plan.preflight_status == "failed"
    assert any(finding.title == "Interface is a trunk" for finding in result.findings)


def test_missing_vlan_fails_access_port_preflight(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local, vlan_present=False)

    result = run_preflight(plan_id)

    assert result.plan.preflight_status == "failed"
    assert any(finding.title == "Target VLAN missing" for finding in result.findings)
