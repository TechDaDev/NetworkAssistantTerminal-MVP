from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import Base, ChangePlan, Device, DeviceCredential, ExecutionLog
from app.services import config_executor, config_planner, config_snapshot
from app.services.config_executor import ConfigExecutionError, execute_change_plan, rollback_change_plan, validate_execution_confirmation, verify_change_plan


class FakeCiscoConnection:
    def __init__(self, *, configured: bool = True):
        self.configured = configured
        self.sent_config_sets: list[list[str]] = []

    def send_command(self, command: str, read_timeout: int = 20):
        if command.startswith("show running-config interface"):
            if self.configured:
                return (
                    "interface Gi0/5\n"
                    " description LAB-PC-01\n"
                    " switchport mode access\n"
                    " switchport access vlan 30\n"
                    " spanning-tree portfast"
                )
            return "interface Gi0/5\n no description"
        if command == "show vlan brief":
            return "30 LAB active"
        if command == "show interfaces status":
            return "Gi0/5 connected 30 a-full a-100"
        if command == "show interfaces trunk":
            return ""
        return ""

    def send_config_set(self, commands):
        self.sent_config_sets.append(list(commands))
        return "\n".join(commands)

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


def _add_plan(session_local, *, status="approved", preflight_status="passed", plan_type="cisco_access_port"):
    with session_local() as session:
        device = Device(ip_address="192.168.88.20", vendor_guess="Cisco", device_type_guess="Switch", confidence="High")
        device.credentials = [
            DeviceCredential(username="admin", encrypted_password="encrypted", connection_type="ssh", platform_hint="cisco_ios")
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
            preflight_status=preflight_status,
            proposed_commands=proposed,
            rollback_commands=rollback,
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
        return FakeCiscoConnection()

    monkeypatch.setattr(config_executor, "_open_cisco_connection", fake_open)

    result = execute_change_plan(plan_id, dry_run=True)

    assert result.dry_run is True
    assert result.log is None
    assert called is False


def test_wrong_confirmation_is_blocked():
    with pytest.raises(ConfigExecutionError):
        validate_execution_confirmation("EXECUTE", 5, "EXECUTE 4")


def test_execution_blocked_without_passed_preflight(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local, preflight_status="warning")

    with pytest.raises(ConfigExecutionError):
        execute_change_plan(plan_id, dry_run=True)


def test_verify_supports_cisco_access_port_plan(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local, status="executed")
    monkeypatch.setattr(config_executor, "_open_cisco_connection", lambda _credential: FakeCiscoConnection(configured=True))

    result = verify_change_plan(plan_id)

    assert result.log.status == "verified"


def test_rollback_supports_cisco_description_plan(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local, status="executed", plan_type="cisco_interface_description")
    monkeypatch.setattr(config_executor, "_open_cisco_connection", lambda _credential: FakeCiscoConnection(configured=False))

    result = rollback_change_plan(plan_id, confirmation=f"ROLLBACK PLAN {plan_id}")

    assert result.log.status == "manual_rollback_success"


def test_save_supports_verified_cisco_interface_plan(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local, status="executed")
    with session_local() as session:
        plan = session.get(ChangePlan, plan_id)
        session.add(
            ExecutionLog(
                plan=plan,
                device=plan.device,
                status="verified",
                started_at=datetime.now(timezone.utc),
                finished_at=datetime.now(timezone.utc),
            )
        )
        session.commit()

    class SaveConnection(FakeCiscoConnection):
        def send_command_timing(self, command: str, read_timeout: int = 60):
            return "OK" if command == "write memory" else ""

    monkeypatch.setattr(config_executor, "_open_cisco_connection", lambda _credential: SaveConnection())

    result = config_executor.save_plan_config(plan_id, confirmation=f"SAVE CONFIG PLAN {plan_id}")

    assert result.log.status == "save_success"
