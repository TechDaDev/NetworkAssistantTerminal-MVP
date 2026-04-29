from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import Base, ChangePlan, Device, DeviceCredential
from app.services import config_executor, config_planner, config_snapshot
from app.services.config_executor import (
    ConfigExecutionError,
    execute_change_plan,
    validate_mikrotik_dhcp_execution_commands,
)


PROPOSED = [
    "/ip pool add name=lab-pool ranges=192.168.50.100-192.168.50.200",
    '/ip dhcp-server add name=lab-dhcp interface=bridge address-pool=lab-pool disabled=no comment="LAB DHCP"',
    "/ip dhcp-server network add address=192.168.50.0/24 gateway=192.168.50.1 dns-server=8.8.8.8,1.1.1.1",
]
ROLLBACK = [
    '/ip dhcp-server remove [find name="lab-dhcp"]',
    '/ip dhcp-server network remove [find address="192.168.50.0/24"]',
    '/ip pool remove [find name="lab-pool"]',
]


class FakeMikroTikConnection:
    def __init__(self, *, verify: bool = True):
        self.verify = verify
        self.commands: list[str] = []

    def send_command(self, command: str, read_timeout: int = 20):
        self.commands.append(command)
        if command == "/ip pool print":
            return "0 name=lab-pool ranges=192.168.50.100-192.168.50.200" if self.verify else ""
        if command == "/ip dhcp-server print":
            return "0 name=lab-dhcp interface=bridge address-pool=lab-pool disabled=no" if self.verify else ""
        if command == "/ip dhcp-server network print":
            return "0 address=192.168.50.0/24 gateway=192.168.50.1 dns-server=8.8.8.8,1.1.1.1" if self.verify else ""
        if command == "/interface print":
            return "0 R name=bridge"
        if command == "/ip address print":
            return "0 address=192.168.50.1/24 interface=bridge"
        return "ok"

    def disconnect(self):
        pass


def _install_temp_db(monkeypatch):
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    monkeypatch.setattr(config_planner, "init_db", lambda: None)
    monkeypatch.setattr(config_planner, "get_session", session_local)
    monkeypatch.setattr(config_executor, "init_db", lambda: None)
    monkeypatch.setattr(config_executor, "get_session", session_local)
    monkeypatch.setattr(config_snapshot, "init_db", lambda: None)
    monkeypatch.setattr(config_snapshot, "get_session", session_local)
    return session_local


def _add_plan(
    session_local,
    *,
    status: str = "approved",
    preflight_status: str = "passed",
    platform: str = "mikrotik_routeros",
    proposed: list[str] | None = None,
    rollback: list[str] | None = None,
) -> int:
    with session_local() as session:
        device = Device(ip_address="192.168.88.1", vendor_guess="MikroTik", device_type_guess="Router", confidence="High")
        device.credentials = [
            DeviceCredential(
                username="admin",
                encrypted_password="encrypted",
                connection_type="ssh",
                platform_hint=platform,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
        ]
        plan = ChangePlan(
            device=device,
            plan_type="mikrotik_dhcp_server",
            title="DHCP",
            description="test",
            risk_level="medium",
            status=status,
            preflight_status=preflight_status,
            proposed_commands="\n".join(proposed or PROPOSED),
            rollback_commands="\n".join(rollback or ROLLBACK),
            validation_findings="[]",
        )
        session.add(plan)
        session.commit()
        return plan.id


def test_dry_run_works_and_executes_nothing(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local)
    called = False

    def fake_open(_credential):
        nonlocal called
        called = True
        return FakeMikroTikConnection()

    monkeypatch.setattr(config_executor, "_open_mikrotik_connection", fake_open)

    result = execute_change_plan(plan_id, dry_run=True)

    assert result.dry_run is True
    assert result.log is None
    assert called is False


def test_non_approved_plan_execution_is_blocked(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local, status="draft")

    with pytest.raises(ConfigExecutionError):
        execute_change_plan(plan_id, dry_run=True)


def test_preflight_warning_blocks_execution(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local, preflight_status="warning")

    with pytest.raises(ConfigExecutionError):
        execute_change_plan(plan_id, dry_run=True)


def test_wrong_confirmation_blocks_execution(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local)

    with pytest.raises(ConfigExecutionError):
        execute_change_plan(plan_id, confirmation=f"EXECUTE {plan_id}")


def test_wrong_credential_platform_blocks_execution(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local, platform="cisco_ios")

    with pytest.raises(ConfigExecutionError):
        execute_change_plan(plan_id, dry_run=True)


def test_unsafe_proposed_commands_are_blocked():
    proposed = list(PROPOSED)
    proposed[0] = "/system reboot"

    with pytest.raises(ConfigExecutionError):
        validate_mikrotik_dhcp_execution_commands(proposed, ROLLBACK)


def test_unsafe_rollback_commands_are_blocked():
    rollback = list(ROLLBACK)
    rollback[0] = "/ip dhcp-server remove [find]"

    with pytest.raises(ConfigExecutionError):
        validate_mikrotik_dhcp_execution_commands(PROPOSED, rollback)


def test_real_execution_requires_confirmation(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local)
    monkeypatch.setattr(config_executor, "_open_mikrotik_connection", lambda _credential: FakeMikroTikConnection())

    result = execute_change_plan(plan_id, confirmation=f"EXECUTE PLAN {plan_id}")

    assert result.log.status == "success"
    assert result.plan.status == "executed"
