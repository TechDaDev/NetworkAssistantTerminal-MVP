import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import Base, ChangePlan, Device, DeviceCredential
from app.services import config_executor
from app.services.config_executor import ConfigExecutionError, execute_change_plan
from app.services.config_snapshot import ConfigSnapshotError


class FakeConnection:
    def __init__(self, verify_output: str = "ok"):
        self.verify_output = verify_output
        self.config_sets = []
        self.commands = []

    def send_command(self, command, read_timeout=60):
        self.commands.append(command)
        return self.verify_output

    def send_config_set(self, commands):
        self.config_sets.append(list(commands))
        return "\n".join(commands)

    def disconnect(self):
        pass


def _install_temp_db(monkeypatch):
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    monkeypatch.setattr(config_executor, "init_db", lambda: None)
    monkeypatch.setattr(config_executor, "get_session", session_local)
    return session_local


def _add_custom_plan(session_local):
    metadata = {
        "platform": "cisco_ios",
        "precheck_commands": ["show ip route"],
        "verification_commands": ["show ip route"],
        "requires_double_confirmation": True,
    }
    with session_local() as session:
        device = Device(ip_address="192.168.88.20", vendor_guess="Cisco")
        device.credentials = [DeviceCredential(username="admin", encrypted_password="x", connection_type="ssh", platform_hint="cisco_ios")]
        session.add(device)
        session.flush()
        plan = ChangePlan(
            device=device,
            plan_type="custom_cisco_plan",
            title="Custom static route",
            description="custom",
            risk_level="high",
            status="approved",
            preflight_status="passed",
            proposed_commands="ip route 10.50.0.0 255.255.255.0 192.168.88.1",
            rollback_commands="no ip route 10.50.0.0 255.255.255.0 192.168.88.1",
            validation_findings="[]",
            custom_plan_metadata_json=json.dumps(metadata),
        )
        session.add(plan)
        session.commit()
        return plan.id


def test_custom_execution_requires_exact_confirmation(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_custom_plan(session_local)

    with pytest.raises(ConfigExecutionError):
        execute_change_plan(plan_id, confirmation="EXECUTE PLAN 1")


def test_custom_execution_requires_double_confirmation(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_custom_plan(session_local)

    with pytest.raises(ConfigExecutionError):
        execute_change_plan(plan_id, confirmation=f"EXECUTE CUSTOM PLAN {plan_id}")


def test_custom_execution_fails_if_snapshot_fails(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_custom_plan(session_local)
    monkeypatch.setattr(config_executor, "_open_cisco_connection", lambda _credential: FakeConnection())
    monkeypatch.setattr(config_executor, "capture_pre_change_snapshot", lambda *_args, **_kwargs: (_ for _ in ()).throw(ConfigSnapshotError("snapshot failed")))

    result = execute_change_plan(
        plan_id,
        confirmation=f"EXECUTE CUSTOM PLAN {plan_id}",
        double_confirmation="I UNDERSTAND THIS MAY DISCONNECT THE NETWORK",
    )

    assert result.log.status == "failed"
    assert "snapshot failed" in result.log.error_message


def test_custom_execution_rolls_back_on_failed_verification(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_custom_plan(session_local)
    fake = FakeConnection(verify_output="error: failed")
    monkeypatch.setattr(config_executor, "_open_cisco_connection", lambda _credential: fake)
    monkeypatch.setattr(config_executor, "capture_pre_change_snapshot", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(config_executor, "capture_pre_rollback_snapshot", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(config_executor, "capture_post_rollback_snapshot", lambda *_args, **_kwargs: object())

    result = execute_change_plan(
        plan_id,
        confirmation=f"EXECUTE CUSTOM PLAN {plan_id}",
        double_confirmation="I UNDERSTAND THIS MAY DISCONNECT THE NETWORK",
    )

    assert result.log.status == "rolled_back"
    assert len(fake.config_sets) >= 2
