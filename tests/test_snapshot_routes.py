from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import server
from app.agent.intent_parser import parse_intent
from app.agent.policy import evaluate_agent_action
from app.models import Base, ChangePlan, Device, DeviceConfigSnapshot, DeviceCredential
from app.services import command_router, config_snapshot
from app.services.command_router import route_local_command


def _install_temp_db(monkeypatch):
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    monkeypatch.setattr(config_snapshot, "init_db", lambda: None)
    monkeypatch.setattr(config_snapshot, "get_session", session_local)
    monkeypatch.setattr(server, "list_snapshots", config_snapshot.list_snapshots)
    monkeypatch.setattr(server, "show_snapshot", config_snapshot.show_snapshot)
    monkeypatch.setattr(command_router, "list_snapshots", config_snapshot.list_snapshots)
    monkeypatch.setattr(command_router, "show_snapshot", config_snapshot.show_snapshot)
    return session_local


def _add_snapshot(session_local) -> tuple[int, int]:
    with session_local() as session:
        device = Device(ip_address="192.168.88.20", vendor_guess="Cisco", device_type_guess="Switch", confidence="High")
        device.credentials = [
            DeviceCredential(username="admin", encrypted_password="encrypted", connection_type="ssh", platform_hint="cisco_ios")
        ]
        plan = ChangePlan(
            device=device,
            plan_type="cisco_interface_description",
            title="Description",
            description="test",
            risk_level="low",
            status="approved",
            preflight_status="passed",
            proposed_commands="interface Gi0/5\n description LAB",
            rollback_commands="interface Gi0/5\n no description",
            validation_findings="[]",
        )
        snapshot = DeviceConfigSnapshot(
            device=device,
            plan_id=1,
            snapshot_type="pre_change",
            platform="cisco_ios",
            content="$ show running-config\nconfig",
            command_outputs_json='{"show running-config": "config"}',
            created_at=datetime.now(timezone.utc),
        )
        session.add(plan)
        session.add(snapshot)
        session.commit()
        return plan.id, snapshot.id


def test_snapshot_list_and_show_service_routes(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    _plan_id, snapshot_id = _add_snapshot(session_local)

    listed = server.snapshots_endpoint()
    shown = server.snapshot_show_endpoint(snapshot_id)

    assert listed["ok"] is True
    assert listed["snapshots"][0]["snapshot_type"] == "pre_change"
    assert shown["snapshot"]["content"] == "$ show running-config\nconfig"


def test_chat_router_lists_and_shows_snapshots(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    _plan_id, snapshot_id = _add_snapshot(session_local)

    listed = route_local_command("list snapshots")
    shown = route_local_command(f"show snapshot {snapshot_id}")

    assert listed.ok is True
    assert shown.ok is True
    assert shown.kind == "snapshot"


def test_agent_snapshot_routes_are_policy_controlled():
    list_intent = parse_intent("list snapshots")
    show_intent = parse_intent("show snapshot 1")
    capture_intent = parse_intent("capture snapshot plan 1")

    assert evaluate_agent_action(list_intent.tool_name, list_intent.args).risk_level == "low"
    assert evaluate_agent_action(show_intent.tool_name, show_intent.args).risk_level == "low"
    capture_decision = evaluate_agent_action(capture_intent.tool_name, capture_intent.args)
    assert capture_decision.risk_level == "medium"
    assert capture_decision.requires_confirmation
