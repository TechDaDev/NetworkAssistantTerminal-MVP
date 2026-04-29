from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import Base, CommandRun, Device, DeviceCredential
from app.services import config_executor, config_planner
from app.services.config_executor import ConfigExecutionError
from app.services.config_planner import create_mikrotik_dhcp_plan, run_preflight


def _install_temp_db(monkeypatch):
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    monkeypatch.setattr(config_planner, "init_db", lambda: None)
    monkeypatch.setattr(config_planner, "get_session", session_local)
    monkeypatch.setattr(config_executor, "init_db", lambda: None)
    monkeypatch.setattr(config_executor, "get_session", session_local)
    return session_local


def _add_device(
    session_local,
    *,
    interface_output: str = "0 R name=bridge type=bridge",
    address_output: str = "0 address=192.168.50.1/24 interface=bridge",
    pool_output: str = "0 name=old-pool ranges=192.168.10.10-192.168.10.20",
    dhcp_output: str = "0 name=old-dhcp interface=bridge",
    dhcp_network_output: str = "0 address=192.168.10.0/24 gateway=192.168.10.1",
    credential_platform: str = "mikrotik_routeros",
) -> None:
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
                platform_hint=credential_platform,
                status="stored",
                created_at=now,
                updated_at=now,
            )
        ]
        outputs = {
            "/interface print": interface_output,
            "/ip address print": address_output,
            "/ip pool print": pool_output,
            "/ip dhcp-server print": dhcp_output,
            "/ip dhcp-server network print": dhcp_network_output,
        }
        device.command_runs = [
            CommandRun(command=command, output=output, success=True, started_at=now, finished_at=now)
            for command, output in outputs.items()
            if output is not None
        ]
        session.add(device)
        session.commit()


def _approved_plan(session_local):
    result = create_mikrotik_dhcp_plan(
        device_ip="192.168.88.1",
        name="lab-dhcp",
        interface="bridge",
        network="192.168.50.0/24",
        gateway="192.168.50.1",
        pool_name="lab-pool",
        pool_range="192.168.50.100-192.168.50.200",
        dns="8.8.8.8,1.1.1.1",
        comment="LAB DHCP",
    )
    with session_local() as session:
        plan = session.get(config_planner.ChangePlan, result.plan.id)
        plan.status = "approved"
        session.commit()
    return result.plan.id


def test_valid_stored_evidence_allows_passed_preflight(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    _add_device(session_local)
    plan_id = _approved_plan(session_local)

    result = run_preflight(plan_id)

    assert result.plan.preflight_status == "passed"
    assert any(finding.title == "Interface found" for finding in result.findings)
    assert any(finding.title == "Gateway address found" for finding in result.findings)


def test_missing_evidence_returns_warning(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    _add_device(
        session_local,
        interface_output=None,
        address_output=None,
        pool_output=None,
        dhcp_output=None,
        dhcp_network_output=None,
    )
    plan_id = _approved_plan(session_local)

    result = run_preflight(plan_id)

    assert result.plan.preflight_status == "warning"
    assert any(finding.title == "DHCP evidence missing" for finding in result.findings)


def test_missing_interface_fails(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    _add_device(session_local, interface_output="0 R name=ether1 type=ether")
    plan_id = _approved_plan(session_local)

    result = run_preflight(plan_id)

    assert result.plan.preflight_status == "failed"
    assert any(finding.title == "Interface not found" for finding in result.findings)


@pytest.mark.parametrize(
    ("pool_output", "dhcp_output", "dhcp_network_output", "title"),
    [
        ("0 name=lab-pool ranges=192.168.50.100-192.168.50.200", "0 name=old-dhcp", "0 address=192.168.10.0/24", "Pool name already exists"),
        ("0 name=old-pool", "0 name=lab-dhcp interface=bridge", "0 address=192.168.10.0/24", "DHCP server name already exists"),
        ("0 name=old-pool", "0 name=old-dhcp", "0 address=192.168.50.0/24 gateway=192.168.50.1", "DHCP network already exists"),
    ],
)
def test_existing_conflicts_fail(monkeypatch, pool_output, dhcp_output, dhcp_network_output, title):
    session_local = _install_temp_db(monkeypatch)
    _add_device(
        session_local,
        pool_output=pool_output,
        dhcp_output=dhcp_output,
        dhcp_network_output=dhcp_network_output,
    )
    plan_id = _approved_plan(session_local)

    result = run_preflight(plan_id)

    assert result.plan.preflight_status == "failed"
    assert any(finding.title == title for finding in result.findings)


def test_wrong_credential_platform_fails(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    _add_device(session_local, credential_platform="cisco_ios")
    plan_id = _approved_plan(session_local)

    result = run_preflight(plan_id)

    assert result.plan.preflight_status == "failed"
    assert any(finding.title == "MikroTik credentials missing" for finding in result.findings)


def test_gateway_missing_warns(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    _add_device(session_local, address_output="0 address=192.168.88.1/24 interface=bridge")
    plan_id = _approved_plan(session_local)

    result = run_preflight(plan_id)

    assert result.plan.preflight_status == "warning"
    assert any(finding.title == "Gateway address not confirmed" for finding in result.findings)


def test_dhcp_execution_dry_run_supported_after_passed_preflight(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    _add_device(session_local)
    plan_id = _approved_plan(session_local)
    result = run_preflight(plan_id)
    assert result.plan.preflight_status == "passed"

    execution = config_executor.execute_change_plan(plan_id, dry_run=True)

    assert execution.dry_run is True
    assert execution.log is None
