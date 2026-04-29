from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.command_policy import CommandPolicyError, validate_readonly_command
from app.models import Base, ChangePlan, Device, DeviceCredential
from app.services import config_snapshot
from app.services.config_snapshot import ConfigSnapshotError, capture_manual_snapshot, snapshot_commands_for_plan


class FakeConnection:
    def __init__(self):
        self.commands: list[str] = []

    def send_command(self, command: str, read_timeout: int = 60):
        self.commands.append(command)
        return f"output for {command}"

    def disconnect(self):
        pass


def _install_temp_db(monkeypatch):
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    monkeypatch.setattr(config_snapshot, "init_db", lambda: None)
    monkeypatch.setattr(config_snapshot, "get_session", session_local)
    return session_local


def _add_plan(session_local, *, plan_type: str, proposed: str = "", platform: str | None = None) -> int:
    with session_local() as session:
        platform = platform or ("mikrotik_routeros" if plan_type.startswith("mikrotik") else "cisco_ios")
        device = Device(ip_address="192.168.88.20", vendor_guess="test", device_type_guess="test", confidence="High")
        device.credentials = [
            DeviceCredential(username="admin", encrypted_password="encrypted", connection_type="ssh", platform_hint=platform)
        ]
        plan = ChangePlan(
            device=device,
            plan_type=plan_type,
            title="test",
            description="test",
            risk_level="medium",
            status="approved",
            preflight_status="passed",
            proposed_commands=proposed,
            rollback_commands="rollback",
            validation_findings="[]",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(plan)
        session.commit()
        return plan.id


def test_cisco_snapshot_command_list_is_read_only(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local, plan_type="cisco_access_port", proposed="interface Gi0/5\n description LAB")
    with session_local() as session:
        plan = session.get(ChangePlan, plan_id)
        command_plan = snapshot_commands_for_plan(plan)

    assert "show running-config" in command_plan.commands
    assert "show running-config interface Gi0/5" in command_plan.commands
    for command in command_plan.commands:
        validate_readonly_command("cisco_ios", command)


def test_mikrotik_snapshot_command_list_is_read_only(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local, plan_type="mikrotik_dhcp_server")
    with session_local() as session:
        plan = session.get(ChangePlan, plan_id)
        command_plan = snapshot_commands_for_plan(plan)

    assert "/export terse" in command_plan.commands
    assert "/ip dhcp-server network print" in command_plan.commands
    for command in command_plan.commands:
        validate_readonly_command("mikrotik_routeros", command)


def test_export_terse_allowed_but_export_file_blocked():
    validate_readonly_command("mikrotik_routeros", "/export terse")
    with pytest.raises(CommandPolicyError):
        validate_readonly_command("mikrotik_routeros", "/export file=backup")


def test_manual_snapshot_capture_saves_outputs(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local, plan_type="mikrotik_address")
    fake = FakeConnection()
    monkeypatch.setattr(config_snapshot, "_open_connection", lambda _credential, _platform: fake)

    snapshot = capture_manual_snapshot(plan_id)

    assert snapshot.id is not None
    assert snapshot.snapshot_type == "manual"
    assert snapshot.platform == "mikrotik_routeros"
    assert "/export terse" in snapshot.command_outputs_json
    assert fake.commands[:3] == ["/export terse", "/interface print", "/ip address print"]


def test_snapshot_blocks_unsupported_plan_type(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local, plan_type="unsupported")

    with pytest.raises(ConfigSnapshotError):
        capture_manual_snapshot(plan_id)
