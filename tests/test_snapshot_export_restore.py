import json
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import server
from app.models import Base, ChangePlan, Device, DeviceConfigSnapshot
from app.services import config_snapshot
from app.services.command_router import route_local_command
from app.services.config_snapshot import (
    ConfigSnapshotError,
    generate_restore_guidance,
    render_snapshot_export,
    write_snapshot_export_file,
)


def _install_temp_db(monkeypatch):
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    monkeypatch.setattr(config_snapshot, "init_db", lambda: None)
    monkeypatch.setattr(config_snapshot, "get_session", session_local)
    monkeypatch.setattr(server, "render_snapshot_export", config_snapshot.render_snapshot_export)
    monkeypatch.setattr(server, "generate_restore_guidance", config_snapshot.generate_restore_guidance)
    return session_local


def _add_snapshot(session_local, *, platform: str = "cisco_ios") -> int:
    with session_local() as session:
        device = Device(
            ip_address="192.168.88.20" if platform == "cisco_ios" else "192.168.88.1",
            vendor_guess="Cisco" if platform == "cisco_ios" else "MikroTik",
            device_type_guess="Switch" if platform == "cisco_ios" else "Router",
            confidence="High",
        )
        plan = ChangePlan(
            device=device,
            plan_type="cisco_access_port" if platform == "cisco_ios" else "mikrotik_dhcp_server",
            title="test",
            description="test",
            risk_level="medium",
            status="executed",
            preflight_status="passed",
            proposed_commands="interface Gi0/5\n description LAB" if platform == "cisco_ios" else "/ip pool add name=lab-pool ranges=192.168.50.100-192.168.50.200",
            rollback_commands="interface Gi0/5\n no description" if platform == "cisco_ios" else '/ip pool remove [find name="lab-pool"]',
            validation_findings="[]",
        )
        session.add(plan)
        session.flush()
        snapshot = DeviceConfigSnapshot(
            device=device,
            plan_id=plan.id,
            snapshot_type="pre_change",
            platform=platform,
            content="$ show running-config\nconfig" if platform == "cisco_ios" else "$ /export terse\n/export content",
            command_outputs_json=json.dumps(
                {"show running-config": "config"}
                if platform == "cisco_ios"
                else {"/export terse": "/export content"}
            ),
            created_at=datetime.now(timezone.utc),
        )
        session.add(snapshot)
        session.commit()
        return snapshot.id


def test_txt_export_works(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    snapshot_id = _add_snapshot(session_local)

    content = render_snapshot_export(snapshot_id, "txt")

    assert "Snapshot ID:" in content
    assert "show running-config" in content
    assert "config" in content


def test_json_export_works_and_parses(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    snapshot_id = _add_snapshot(session_local)

    data = json.loads(render_snapshot_export(snapshot_id, "json"))

    assert data["id"] == snapshot_id
    assert data["command_outputs"]["show running-config"] == "config"


def test_markdown_export_works(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    snapshot_id = _add_snapshot(session_local)

    content = render_snapshot_export(snapshot_id, "md")

    assert f"# Config Snapshot {snapshot_id}" in content
    assert "```text" in content


def test_unsupported_format_is_rejected(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    snapshot_id = _add_snapshot(session_local)

    with pytest.raises(ConfigSnapshotError):
        render_snapshot_export(snapshot_id, "html")


def test_overwrite_blocked_without_force(monkeypatch, tmp_path):
    session_local = _install_temp_db(monkeypatch)
    snapshot_id = _add_snapshot(session_local)
    output = tmp_path / "snapshot.txt"
    output.write_text("existing", encoding="utf-8")

    with pytest.raises(ConfigSnapshotError):
        write_snapshot_export_file(snapshot_id, "txt", str(output), force=False)


def test_overwrite_works_with_force(monkeypatch, tmp_path):
    session_local = _install_temp_db(monkeypatch)
    snapshot_id = _add_snapshot(session_local)
    output = tmp_path / "snapshot.txt"
    output.write_text("existing", encoding="utf-8")

    result = write_snapshot_export_file(snapshot_id, "txt", str(output), force=True)

    assert result.bytes_written > 0
    assert "Network Assistant Config Snapshot" in output.read_text(encoding="utf-8")


def test_server_export_returns_content(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    snapshot_id = _add_snapshot(session_local)

    response = server.snapshot_export_endpoint(snapshot_id, format="json")

    assert response["ok"] is True
    assert json.loads(response["content"])["id"] == snapshot_id


def test_cisco_restore_guidance_no_automatic_restore(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    snapshot_id = _add_snapshot(session_local, platform="cisco_ios")

    guidance = generate_restore_guidance(snapshot_id)
    text = "\n".join(guidance.warnings + guidance.recommended_steps)

    assert "configure replace" in text
    assert "not suggested" in text
    assert "no description" in guidance.rollback_commands


def test_mikrotik_restore_guidance_warns_against_import(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    snapshot_id = _add_snapshot(session_local, platform="mikrotik_routeros")

    guidance = generate_restore_guidance(snapshot_id)

    assert any("/import" in warning for warning in guidance.warnings)
    assert '/ip pool remove [find name="lab-pool"]' in guidance.rollback_commands


def test_chat_restore_guidance_does_not_execute(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    snapshot_id = _add_snapshot(session_local)
    monkeypatch.setattr("app.services.command_router.generate_restore_guidance", config_snapshot.generate_restore_guidance)

    result = route_local_command(f"snapshot restore guidance {snapshot_id}")

    assert result.ok is True
    assert result.kind == "snapshot"
