from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import server
from app.models import Base, ChangePlan, Device, DeviceCredential
from app.services import config_executor, config_planner, config_snapshot
from app.services.config_executor import ConfigExecutionError, rollback_change_plan, save_plan_config, verify_change_plan
from app.services.command_router import route_local_command


PROPOSED = "\n".join(
    [
        "/ip pool add name=lab-pool ranges=192.168.50.100-192.168.50.200",
        "/ip dhcp-server add name=lab-dhcp interface=bridge address-pool=lab-pool disabled=no",
        "/ip dhcp-server network add address=192.168.50.0/24 gateway=192.168.50.1",
    ]
)
ROLLBACK = "\n".join(
    [
        '/ip dhcp-server remove [find name="lab-dhcp"]',
        '/ip dhcp-server network remove [find address="192.168.50.0/24"]',
        '/ip pool remove [find name="lab-pool"]',
    ]
)


class FakeMikroTikConnection:
    def __init__(self, *, configured: bool = True):
        self.configured = configured
        self.commands: list[str] = []

    def send_command(self, command: str, read_timeout: int = 20):
        self.commands.append(command)
        if command == "/ip pool print":
            return "0 name=lab-pool ranges=192.168.50.100-192.168.50.200" if self.configured else ""
        if command == "/ip dhcp-server print":
            return "0 name=lab-dhcp interface=bridge address-pool=lab-pool" if self.configured else ""
        if command == "/ip dhcp-server network print":
            return "0 address=192.168.50.0/24 gateway=192.168.50.1" if self.configured else ""
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
    monkeypatch.setattr(server, "init_db", lambda: None, raising=False)
    return session_local


def _add_plan(session_local, *, status="executed") -> int:
    with session_local() as session:
        device = Device(ip_address="192.168.88.1", vendor_guess="MikroTik", device_type_guess="Router", confidence="High")
        device.credentials = [
            DeviceCredential(username="admin", encrypted_password="encrypted", connection_type="ssh", platform_hint="mikrotik_routeros")
        ]
        plan = ChangePlan(
            device=device,
            plan_type="mikrotik_dhcp_server",
            title="DHCP",
            description="test",
            risk_level="medium",
            status=status,
            preflight_status="passed",
            proposed_commands=PROPOSED,
            rollback_commands=ROLLBACK,
            validation_findings="[]",
        )
        session.add(plan)
        session.commit()
        return plan.id


def test_verify_supports_dhcp_plans(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local)
    monkeypatch.setattr(config_executor, "_open_mikrotik_connection", lambda _credential: FakeMikroTikConnection(configured=True))

    result = verify_change_plan(plan_id)

    assert result.log.status == "verified"


def test_rollback_supports_dhcp_plans_with_confirmation(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local)
    monkeypatch.setattr(config_executor, "_open_mikrotik_connection", lambda _credential: FakeMikroTikConnection(configured=False))

    result = rollback_change_plan(plan_id, confirmation=f"ROLLBACK PLAN {plan_id}")

    assert result.log.status == "manual_rollback_success"
    assert result.plan.status == "rolled_back"


def test_rollback_wrong_confirmation_blocks(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local)

    with pytest.raises(ConfigExecutionError):
        rollback_change_plan(plan_id, confirmation=f"ROLLBACK {plan_id}")


def test_save_refuses_for_dhcp_plan(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local)

    with pytest.raises(ConfigExecutionError, match="RouterOS applies DHCP changes immediately"):
        save_plan_config(plan_id, confirmation=f"SAVE CONFIG PLAN {plan_id}")


def test_server_execution_requires_confirmation(monkeypatch):
    monkeypatch.setattr(server, "execute_change_plan", lambda *_args, **_kwargs: (_ for _ in ()).throw(ConfigExecutionError("blocked")))

    with pytest.raises(Exception):
        server.plan_execute_endpoint(5, server.PlanExecutionRequest(confirmation=None), dry_run=False)


def test_chat_does_not_execute_dhcp_plans():
    result = route_local_command("execute plan 5")

    assert not result.ok
    assert "direct CLI confirmation" in result.message
