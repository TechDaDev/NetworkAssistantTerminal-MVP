from datetime import datetime, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.models import Base, ChangePlan, Device, DeviceConfigSnapshot, DeviceCredential
from app.services import config_executor, config_planner, config_snapshot
from app.services.config_executor import execute_change_plan
from app.services.config_snapshot import ConfigSnapshotError


PROPOSED = [
    "/ip pool add name=lab-pool ranges=192.168.50.100-192.168.50.200",
    "/ip dhcp-server add name=lab-dhcp interface=bridge address-pool=lab-pool disabled=no",
    "/ip dhcp-server network add address=192.168.50.0/24 gateway=192.168.50.1",
]
ROLLBACK = [
    '/ip dhcp-server remove [find name="lab-dhcp"]',
    '/ip dhcp-server network remove [find address="192.168.50.0/24"]',
    '/ip pool remove [find name="lab-pool"]',
]


class FakeMikroTikConnection:
    def __init__(self):
        self.commands: list[str] = []

    def send_command(self, command: str, read_timeout: int = 20):
        self.commands.append(command)
        if command == "/ip pool print":
            return "0 name=lab-pool ranges=192.168.50.100-192.168.50.200"
        if command == "/ip dhcp-server print":
            return "0 name=lab-dhcp interface=bridge address-pool=lab-pool disabled=no"
        if command == "/ip dhcp-server network print":
            return "0 address=192.168.50.0/24 gateway=192.168.50.1"
        if command == "/interface print":
            return "0 R name=bridge"
        if command == "/ip address print":
            return "0 address=192.168.50.1/24 interface=bridge"
        if command == "/export terse":
            return "/ip address add address=192.168.50.1/24 interface=bridge"
        return "ok"

    def disconnect(self):
        pass


def _install_temp_db(monkeypatch):
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    for module in (config_planner, config_executor, config_snapshot):
        monkeypatch.setattr(module, "init_db", lambda: None)
        monkeypatch.setattr(module, "get_session", session_local)
    return session_local


def _add_plan(session_local) -> int:
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
            status="approved",
            preflight_status="passed",
            proposed_commands="\n".join(PROPOSED),
            rollback_commands="\n".join(ROLLBACK),
            validation_findings="[]",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(plan)
        session.commit()
        return plan.id


def test_pre_change_snapshot_is_captured_before_execution(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local)
    fake = FakeMikroTikConnection()
    monkeypatch.setattr(config_executor, "_open_mikrotik_connection", lambda _credential: fake)

    result = execute_change_plan(plan_id, confirmation=f"EXECUTE PLAN {plan_id}")

    assert result.log.status == "success"
    assert fake.commands.index("/export terse") < fake.commands.index(PROPOSED[0])
    with session_local() as session:
        snapshots = session.scalars(select(DeviceConfigSnapshot)).all()
        assert {snapshot.snapshot_type for snapshot in snapshots} >= {"pre_change", "post_change"}


def test_execution_blocked_if_pre_change_snapshot_fails(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local)
    fake = FakeMikroTikConnection()
    monkeypatch.setattr(config_executor, "_open_mikrotik_connection", lambda _credential: fake)
    monkeypatch.setattr(
        config_executor,
        "capture_pre_change_snapshot",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ConfigSnapshotError("snapshot failed")),
    )

    result = execute_change_plan(plan_id, confirmation=f"EXECUTE PLAN {plan_id}")

    assert result.log.status == "failed"
    assert result.plan.status == "approved"
    assert PROPOSED[0] not in fake.commands
    assert "Execution was not started" in result.message


def test_post_change_snapshot_failure_logs_warning_without_failing_execution(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    plan_id = _add_plan(session_local)
    monkeypatch.setattr(config_executor, "_open_mikrotik_connection", lambda _credential: FakeMikroTikConnection())
    monkeypatch.setattr(
        config_executor,
        "capture_post_change_snapshot",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ConfigSnapshotError("post snapshot failed")),
    )

    result = execute_change_plan(plan_id, confirmation=f"EXECUTE PLAN {plan_id}")

    assert result.log.status == "success"
    assert "POST-CHANGE SNAPSHOT WARNING" in result.log.post_check_output
