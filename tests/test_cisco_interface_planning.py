from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import Base, CommandRun, Device
from app.services import config_planner
from app.services.config_planner import (
    ConfigPlanError,
    create_cisco_access_port_plan,
    create_cisco_description_plan,
    preflight_findings,
    validate_cisco_interface_plan,
)


def _install_temp_db(monkeypatch):
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    monkeypatch.setattr(config_planner, "init_db", lambda: None)
    monkeypatch.setattr(config_planner, "get_session", session_local)
    return session_local


def _add_device(session_local, *, trunk: bool = False):
    now = datetime.now(timezone.utc)
    status_output = "Port      Name Status       Vlan Duplex Speed Type\nGi0/5          connected    30   a-full a-100 10/100"
    trunk_output = "Port        Mode         Encapsulation  Status        Native vlan\nGi0/5       on           802.1q         trunking      1" if trunk else ""
    with session_local() as session:
        device = Device(
            ip_address="192.168.88.20",
            vendor_guess="Cisco",
            device_type_guess="Switch",
            confidence="High",
        )
        device.command_runs = [
            CommandRun(command="show interfaces status", output=status_output, success=True, started_at=now, finished_at=now),
            CommandRun(command="show interfaces trunk", output=trunk_output, success=True, started_at=now, finished_at=now),
            CommandRun(command="show vlan brief", output="1 default active\n30 LAB active", success=True, started_at=now, finished_at=now),
        ]
        session.add(device)
        session.commit()


def test_valid_description_plan_saves(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    _add_device(session_local)

    result = create_cisco_description_plan("192.168.88.20", "Gi0/5", "LAB-PC-01")

    assert result.plan.plan_type == "cisco_interface_description"
    assert "description LAB-PC-01" in result.plan.proposed_commands
    assert "no description" in result.plan.rollback_commands


def test_valid_access_port_plan_saves(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    _add_device(session_local)

    result = create_cisco_access_port_plan("192.168.88.20", "Gi0/5", 30, "LAB-PC-01")

    assert result.plan.plan_type == "cisco_access_port"
    assert "switchport access vlan 30" in result.plan.proposed_commands
    assert "no switchport access vlan 30" in result.plan.rollback_commands


def test_invalid_vlan_id_is_rejected(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    _add_device(session_local)

    with pytest.raises(ConfigPlanError):
        create_cisco_access_port_plan("192.168.88.20", "Gi0/5", 5000, None)


def test_unsafe_interface_is_rejected(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    _add_device(session_local)

    with pytest.raises(ConfigPlanError):
        create_cisco_description_plan("192.168.88.20", "Gi0/5;reload", "LAB")


def test_interface_range_is_rejected(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    _add_device(session_local)

    with pytest.raises(ConfigPlanError):
        create_cisco_description_plan("192.168.88.20", "Gi0/5-Gi0/10", "LAB")


def test_unsafe_description_is_rejected(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    _add_device(session_local)

    with pytest.raises(ConfigPlanError):
        create_cisco_description_plan("192.168.88.20", "Gi0/5", "LAB; reload")


def test_trunk_conflict_blocks_access_port_plan(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    _add_device(session_local, trunk=True)

    result = create_cisco_access_port_plan("192.168.88.20", "Gi0/5", 30, "LAB-PC-01")

    assert result.plan.status == "blocked"
    assert any(finding.title == "Interface appears to be a trunk" and finding.severity == "high" for finding in result.findings)


def test_missing_evidence_warns():
    device = Device(ip_address="192.168.88.20", vendor_guess="Cisco", device_type_guess="Switch", confidence="High")
    device.command_runs = []

    findings = validate_cisco_interface_plan(device, "Gi0/5", vlan_id=30, access_port=True)

    assert any(finding.title == "Validation incomplete" for finding in findings)
    assert any(finding.severity == "medium" for finding in findings)


def test_preflight_supports_new_cisco_interface_plan_type_with_safety_findings():
    device = Device(ip_address="192.168.88.20", vendor_guess="Cisco", device_type_guess="Switch", confidence="High")
    plan = config_planner.ChangePlan(
        id=1,
        device=device,
        plan_type="cisco_access_port",
        status="approved",
        proposed_commands="interface Gi0/5\n switchport mode access\n switchport access vlan 30\n spanning-tree portfast",
        rollback_commands="interface Gi0/5\n no switchport access vlan 30\n no spanning-tree portfast",
    )

    findings = preflight_findings(plan)

    assert any(finding.title == "No credentials stored" for finding in findings)
    assert not any("not implemented yet" in finding.detail for finding in findings)
