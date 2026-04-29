from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import Base, CommandRun, Device, DeviceCredential
from app.services import config_planner
from app.services.config_planner import ConfigPlanError, create_mikrotik_dhcp_plan, preflight_findings, run_preflight


def _install_temp_db(monkeypatch):
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    monkeypatch.setattr(config_planner, "init_db", lambda: None)
    monkeypatch.setattr(config_planner, "get_session", session_local)
    return session_local


def _add_device(session_local, *, with_evidence: bool = True) -> None:
    now = datetime.now(timezone.utc)
    with session_local() as session:
        device = Device(
            ip_address="192.168.88.1",
            vendor_guess="MikroTik",
            device_type_guess="Router",
            confidence="High",
        )
        device.credentials = [
            DeviceCredential(
                username="admin",
                encrypted_password="encrypted",
                connection_type="ssh",
                port=22,
                platform_hint="mikrotik_routeros",
                status="stored",
                created_at=now,
                updated_at=now,
            )
        ]
        if with_evidence:
            device.command_runs = [
                CommandRun(command="/interface print", output="0 R bridge bridge", success=True, started_at=now, finished_at=now),
                CommandRun(command="/ip pool print", output="0 name=old-pool ranges=192.168.10.10-192.168.10.20", success=True, started_at=now, finished_at=now),
                CommandRun(command="/ip dhcp-server print", output="0 name=old-dhcp interface=bridge", success=True, started_at=now, finished_at=now),
                CommandRun(command="/ip dhcp-server network print", output="0 address=192.168.10.0/24 gateway=192.168.10.1", success=True, started_at=now, finished_at=now),
                CommandRun(command="/ip address print", output="0 address=192.168.50.1/24 interface=bridge", success=True, started_at=now, finished_at=now),
            ]
        session.add(device)
        session.commit()


def _create_plan(monkeypatch, **overrides):
    session_local = _install_temp_db(monkeypatch)
    _add_device(session_local)
    values = {
        "device_ip": "192.168.88.1",
        "name": "lab-dhcp",
        "interface": "bridge",
        "network": "192.168.50.0/24",
        "gateway": "192.168.50.1",
        "pool_name": "lab-pool",
        "pool_range": "192.168.50.100-192.168.50.200",
        "dns": "8.8.8.8,1.1.1.1",
        "comment": "LAB DHCP",
    }
    values.update(overrides)
    return create_mikrotik_dhcp_plan(**values)


def test_valid_mikrotik_dhcp_plan_saves(monkeypatch):
    result = _create_plan(monkeypatch)

    assert result.plan.plan_type == "mikrotik_dhcp_server"
    assert "/ip pool add name=lab-pool ranges=192.168.50.100-192.168.50.200" in result.plan.proposed_commands
    assert "/ip dhcp-server add name=lab-dhcp interface=bridge address-pool=lab-pool disabled=no" in result.plan.proposed_commands
    assert "dns-server=8.8.8.8,1.1.1.1" in result.plan.proposed_commands
    assert '/ip pool remove [find name="lab-pool"]' in result.plan.rollback_commands


def test_optional_dns_and_comment_are_omitted(monkeypatch):
    result = _create_plan(monkeypatch, dns=None, comment=None)

    assert "dns-server=" not in result.plan.proposed_commands
    assert "comment=" not in result.plan.proposed_commands


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("network", "192.168.50.1/24"),
        ("network", "8.8.8.0/24"),
        ("gateway", "192.168.51.1"),
        ("pool_range", "192.168.51.100-192.168.51.200"),
        ("pool_range", "192.168.50.200-192.168.50.100"),
        ("name", "lab;dhcp"),
        ("pool_name", "lab pool"),
        ("comment", "LAB; DHCP"),
        ("dns", "not-an-ip"),
    ],
)
def test_invalid_inputs_are_rejected(monkeypatch, field, value):
    with pytest.raises(ConfigPlanError):
        _create_plan(monkeypatch, **{field: value})


def test_stored_evidence_conflicts_warn(monkeypatch):
    result = _create_plan(monkeypatch, name="old-dhcp", pool_name="old-pool", network="192.168.10.0/24", gateway="192.168.10.1", pool_range="192.168.10.100-192.168.10.120")

    titles = {finding.title for finding in result.findings}
    assert "Pool name may already exist" in titles
    assert "DHCP server name may already exist" in titles
    assert "DHCP network may already exist" in titles


def test_missing_evidence_warns(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    _add_device(session_local, with_evidence=False)

    result = create_mikrotik_dhcp_plan(
        device_ip="192.168.88.1",
        name="lab-dhcp",
        interface="bridge",
        network="192.168.50.0/24",
        gateway="192.168.50.1",
        pool_name="lab-pool",
        pool_range="192.168.50.100-192.168.50.200",
    )

    assert any(finding.title == "Validation incomplete" for finding in result.findings)


def test_preflight_requires_approval_for_dhcp_plan(monkeypatch):
    result = _create_plan(monkeypatch)

    findings = preflight_findings(result.plan)

    assert any(finding.title == "Plan is not approved" for finding in findings)
    assert not any("not implemented yet" in finding.detail for finding in findings)


def test_preflight_refresh_uses_only_dhcp_readonly_commands(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    _add_device(session_local)
    result = create_mikrotik_dhcp_plan(
        device_ip="192.168.88.1",
        name="lab-dhcp",
        interface="bridge",
        network="192.168.50.0/24",
        gateway="192.168.50.1",
        pool_name="lab-pool",
        pool_range="192.168.50.100-192.168.50.200",
    )
    with session_local() as session:
        plan = session.get(config_planner.ChangePlan, result.plan.id)
        plan.status = "approved"
        session.commit()

    from app.services.device_connection import CommandResult

    now = datetime.now(timezone.utc)
    commands: list[str] = []

    def fake_readonly(ip_address, command):
        commands.append(command)
        return CommandResult(
            ip_address=ip_address,
            command=command,
            output="",
            success=True,
            error_message=None,
            started_at=now,
            finished_at=now,
        )

    monkeypatch.setattr(config_planner, "run_readonly_command", fake_readonly)
    monkeypatch.setattr(config_planner, "run_readonly_profile_collection", lambda *_args, **_kwargs: pytest.fail("unexpected collection"))

    preflight = run_preflight(result.plan.id, refresh=True)

    assert preflight.plan.preflight_status == "passed"
    assert commands == [
        "/interface print",
        "/ip address print",
        "/ip pool print",
        "/ip dhcp-server print",
        "/ip dhcp-server network print",
    ]
