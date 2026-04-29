from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.command_policy import CommandPolicyError, validate_readonly_command
from app.database import get_session, init_db
from app.models import ChangePlan, Device, DeviceConfigSnapshot, DeviceCredential
from app.services.security import CredentialSecurityError, decrypt_secret


class ConfigSnapshotError(RuntimeError):
    """Raised when a read-only config snapshot cannot be captured safely."""


@dataclass(frozen=True)
class SnapshotCommandPlan:
    platform: str
    commands: tuple[str, ...]


@dataclass(frozen=True)
class SnapshotExportResult:
    snapshot_id: int
    export_format: str
    output_path: str
    bytes_written: int


@dataclass(frozen=True)
class SnapshotRestoreGuidance:
    snapshot_id: int
    platform: str
    title: str
    summary: str
    warnings: list[str]
    recommended_steps: list[str]
    rollback_commands: list[str]


def capture_pre_change_snapshot(
    plan_id: int,
    connection=None,
    execution_log_id: int | None = None,
) -> DeviceConfigSnapshot:
    return _capture_plan_snapshot(plan_id, "pre_change", connection=connection, execution_log_id=execution_log_id)


def capture_post_change_snapshot(
    plan_id: int,
    connection=None,
    execution_log_id: int | None = None,
) -> DeviceConfigSnapshot:
    return _capture_plan_snapshot(plan_id, "post_change", connection=connection, execution_log_id=execution_log_id)


def capture_pre_rollback_snapshot(
    plan_id: int,
    connection=None,
    execution_log_id: int | None = None,
) -> DeviceConfigSnapshot:
    return _capture_plan_snapshot(plan_id, "pre_rollback", connection=connection, execution_log_id=execution_log_id)


def capture_post_rollback_snapshot(
    plan_id: int,
    connection=None,
    execution_log_id: int | None = None,
) -> DeviceConfigSnapshot:
    return _capture_plan_snapshot(plan_id, "post_rollback", connection=connection, execution_log_id=execution_log_id)


def capture_manual_snapshot(plan_id: int) -> DeviceConfigSnapshot:
    return _capture_plan_snapshot(plan_id, "manual")


def list_snapshots(device_ip: str | None = None, plan_id: int | None = None) -> list[DeviceConfigSnapshot]:
    init_db()
    with get_session() as session:
        statement = select(DeviceConfigSnapshot).options(selectinload(DeviceConfigSnapshot.device))
        if device_ip:
            statement = statement.join(Device).where(Device.ip_address == device_ip)
        if plan_id is not None:
            statement = statement.where(DeviceConfigSnapshot.plan_id == plan_id)
        statement = statement.order_by(DeviceConfigSnapshot.created_at.desc())
        return list(session.scalars(statement).all())


def show_snapshot(snapshot_id: int) -> DeviceConfigSnapshot | None:
    init_db()
    with get_session() as session:
        return session.scalar(
            select(DeviceConfigSnapshot)
            .options(selectinload(DeviceConfigSnapshot.device))
            .where(DeviceConfigSnapshot.id == snapshot_id)
        )


def render_snapshot_export(snapshot_id: int, export_format: str) -> str:
    snapshot = show_snapshot(snapshot_id)
    if snapshot is None:
        raise ConfigSnapshotError(f"Snapshot {snapshot_id} not found.")
    normalized = export_format.lower().strip()
    if normalized == "txt":
        return _render_txt_export(snapshot)
    if normalized == "json":
        return _render_json_export(snapshot)
    if normalized == "md":
        return _render_markdown_export(snapshot)
    raise ConfigSnapshotError("Unsupported snapshot export format. Use txt, json, or md.")


def write_snapshot_export_file(
    snapshot_id: int,
    export_format: str,
    output_path: str,
    force: bool = False,
) -> SnapshotExportResult:
    content = render_snapshot_export(snapshot_id, export_format)
    path = Path(output_path).expanduser()
    if path.exists() and not force:
        raise ConfigSnapshotError(f"Output file already exists: {path}. Use --force to overwrite.")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return SnapshotExportResult(
        snapshot_id=snapshot_id,
        export_format=export_format.lower().strip(),
        output_path=str(path),
        bytes_written=len(content.encode("utf-8")),
    )


def generate_restore_guidance(snapshot_id: int) -> SnapshotRestoreGuidance:
    snapshot = show_snapshot(snapshot_id)
    if snapshot is None:
        raise ConfigSnapshotError(f"Snapshot {snapshot_id} not found.")
    rollback = _linked_plan_rollback(snapshot)
    platform = snapshot.platform or "unknown"
    warnings = [
        "Restore guidance is informational only. No commands were executed.",
        "Review current device state before making any manual recovery change.",
    ]
    steps = [
        "Export this snapshot and keep it with the change record.",
        "Compare current read-only device state with the snapshot content.",
    ]
    if platform == "cisco_ios":
        title = "Cisco IOS Restore Guidance"
        summary = "This snapshot is recovery evidence, not an automatic restore file."
        warnings.extend(
            [
                "Do not blindly paste full running-config output into configuration mode.",
                "configure replace is not suggested by this assistant in this phase.",
            ]
        )
        if rollback:
            steps.append("Review the linked plan rollback commands below before considering manual recovery.")
        steps.extend(
            [
                "Use read-only show commands to identify exactly what changed.",
                "Create a new reviewed and approved plan for any corrective change.",
            ]
        )
    elif platform == "mikrotik_routeros":
        title = "MikroTik RouterOS Restore Guidance"
        summary = "RouterOS changes are applied immediately; this snapshot is manual recovery evidence."
        warnings.extend(
            [
                "Do not use /import blindly from this snapshot.",
                "This assistant will not execute restore commands from snapshot content.",
            ]
        )
        if rollback:
            steps.append("Review the linked plan rollback commands below before considering manual recovery.")
        steps.extend(
            [
                "Manually review /export terse output and compare it with current read-only state.",
                "Create a new reviewed and approved plan for any corrective change.",
            ]
        )
    else:
        title = "Generic Restore Guidance"
        summary = "The platform is unknown; treat this snapshot as manual recovery evidence only."
        warnings.append("No platform-specific restore workflow is available.")
        if rollback:
            steps.append("Review the linked plan rollback commands below if they apply to the current device state.")
    return SnapshotRestoreGuidance(
        snapshot_id=snapshot.id,
        platform=platform,
        title=title,
        summary=summary,
        warnings=warnings,
        recommended_steps=steps,
        rollback_commands=rollback,
    )


def snapshot_commands_for_plan(plan: ChangePlan) -> SnapshotCommandPlan:
    platform = _platform_for_plan(plan)
    commands: list[str]
    if platform == "cisco_ios":
        commands = [
            "show running-config",
            "show vlan brief",
            "show interfaces status",
            "show interfaces trunk",
        ]
        interface = _cisco_interface_from_plan(plan)
        if interface:
            commands.append(f"show running-config interface {interface}")
    elif platform == "mikrotik_routeros":
        commands = [
            "/export terse",
            "/interface print",
            "/ip address print",
        ]
        if plan.plan_type == "mikrotik_dhcp_server":
            commands.extend(
                [
                    "/ip pool print",
                    "/ip dhcp-server print",
                    "/ip dhcp-server network print",
                ]
            )
    else:
        raise ConfigSnapshotError(f"Snapshots are not supported for platform `{platform}`.")

    for command in commands:
        _validate_snapshot_command(platform, command)
    return SnapshotCommandPlan(platform=platform, commands=tuple(commands))


def _capture_plan_snapshot(
    plan_id: int,
    snapshot_type: str,
    connection=None,
    execution_log_id: int | None = None,
) -> DeviceConfigSnapshot:
    init_db()
    with get_session() as session:
        plan = _load_plan(session, plan_id)
        if plan.device is None:
            raise ConfigSnapshotError("Plan target device is missing from inventory.")
        command_plan = snapshot_commands_for_plan(plan)
        device_id = plan.device.id
        credential = _credential_for_snapshot(plan.device, command_plan.platform) if connection is None else None

    close_connection = False
    active_connection = connection
    try:
        if active_connection is None:
            if credential is None:
                raise ConfigSnapshotError("Stored credentials are required to capture a config snapshot.")
            active_connection = _open_connection(credential, command_plan.platform)
            close_connection = True
        outputs = _run_snapshot_commands(active_connection, command_plan.platform, command_plan.commands)
    except ConfigSnapshotError:
        raise
    except Exception as exc:
        raise ConfigSnapshotError(str(exc)) from exc
    finally:
        if close_connection and active_connection is not None:
            active_connection.disconnect()

    content = _render_snapshot_content(outputs)
    with get_session() as session:
        device = session.get(Device, device_id)
        if device is None:
            raise ConfigSnapshotError("Snapshot target device disappeared before saving.")
        snapshot = DeviceConfigSnapshot(
            device=device,
            plan_id=plan_id,
            execution_log_id=execution_log_id,
            snapshot_type=snapshot_type,
            platform=command_plan.platform,
            content=content,
            command_outputs_json=json.dumps(outputs, indent=2),
            created_at=datetime.now(timezone.utc),
        )
        session.add(snapshot)
        session.commit()
        return session.scalar(
            select(DeviceConfigSnapshot)
            .options(selectinload(DeviceConfigSnapshot.device))
            .where(DeviceConfigSnapshot.id == snapshot.id)
        )


def _run_snapshot_commands(connection, platform: str, commands: tuple[str, ...]) -> dict[str, str]:
    outputs: dict[str, str] = {}
    for command in commands:
        _validate_snapshot_command(platform, command)
        outputs[command] = connection.send_command(command, read_timeout=60)
    return outputs


def _render_snapshot_content(outputs: dict[str, str]) -> str:
    chunks = [f"$ {command}\n{output}" for command, output in outputs.items()]
    return "\n\n".join(chunks)


def _render_txt_export(snapshot: DeviceConfigSnapshot) -> str:
    commands = _command_outputs(snapshot)
    lines = [
        "Network Assistant Config Snapshot",
        f"Snapshot ID: {snapshot.id}",
        f"Device ID: {snapshot.device_id}",
        f"Device IP: {snapshot.device.ip_address if snapshot.device else '--'}",
        f"Plan ID: {snapshot.plan_id if snapshot.plan_id is not None else '--'}",
        f"Execution Log ID: {snapshot.execution_log_id if snapshot.execution_log_id is not None else '--'}",
        f"Snapshot Type: {snapshot.snapshot_type}",
        f"Platform: {snapshot.platform or '--'}",
        f"Created At: {_dt(snapshot.created_at)}",
        "Captured Commands:",
    ]
    lines.extend(f"- {command}" for command in commands)
    lines.extend(["", "Content:", snapshot.content or ""])
    return "\n".join(lines) + "\n"


def _render_json_export(snapshot: DeviceConfigSnapshot) -> str:
    data = {
        "id": snapshot.id,
        "device": {
            "id": snapshot.device_id,
            "ip_address": snapshot.device.ip_address if snapshot.device else None,
        },
        "plan_id": snapshot.plan_id,
        "execution_log_id": snapshot.execution_log_id,
        "snapshot_type": snapshot.snapshot_type,
        "platform": snapshot.platform,
        "created_at": _dt(snapshot.created_at),
        "command_outputs": _command_outputs(snapshot),
        "content": snapshot.content or "",
    }
    return json.dumps(data, indent=2) + "\n"


def _render_markdown_export(snapshot: DeviceConfigSnapshot) -> str:
    outputs = _command_outputs(snapshot)
    lines = [
        f"# Config Snapshot {snapshot.id}",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Device ID | {snapshot.device_id} |",
        f"| Device IP | {snapshot.device.ip_address if snapshot.device else '--'} |",
        f"| Plan ID | {snapshot.plan_id if snapshot.plan_id is not None else '--'} |",
        f"| Execution Log ID | {snapshot.execution_log_id if snapshot.execution_log_id is not None else '--'} |",
        f"| Snapshot Type | {snapshot.snapshot_type} |",
        f"| Platform | {snapshot.platform or '--'} |",
        f"| Created At | {_dt(snapshot.created_at)} |",
        "",
        "## Captured Commands",
        "",
    ]
    lines.extend(f"- `{command}`" for command in outputs)
    lines.extend(
        [
            "",
            "## Notes",
            "",
            "This is read-only snapshot evidence. It is not an automatic restore file.",
            "",
            "## Command Outputs",
            "",
        ]
    )
    for command, output in outputs.items():
        lines.extend([f"### `{command}`", "", "```text", output, "```", ""])
    if not outputs:
        lines.extend(["```text", snapshot.content or "", "```", ""])
    return "\n".join(lines)


def _command_outputs(snapshot: DeviceConfigSnapshot) -> dict[str, str]:
    try:
        data = json.loads(snapshot.command_outputs_json or "{}")
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(key): str(value) for key, value in data.items()}


def _linked_plan_rollback(snapshot: DeviceConfigSnapshot) -> list[str]:
    if snapshot.plan_id is None:
        return []
    with get_session() as session:
        plan = session.get(ChangePlan, snapshot.plan_id)
        if plan is None:
            return []
        return [line.strip() for line in (plan.rollback_commands or "").splitlines() if line.strip()]


def _dt(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _validate_snapshot_command(platform: str, command: str) -> None:
    lowered = command.lower()
    if "/export file" in lowered or "/import" in lowered or lowered.startswith("/file"):
        raise ConfigSnapshotError("Snapshot command is not read-only.")
    try:
        validate_readonly_command(platform, command)
    except CommandPolicyError as exc:
        raise ConfigSnapshotError(str(exc)) from exc


def _load_plan(session, plan_id: int) -> ChangePlan:
    plan = session.scalar(
        select(ChangePlan)
        .options(selectinload(ChangePlan.device).selectinload(Device.credentials))
        .where(ChangePlan.id == plan_id)
    )
    if plan is None:
        raise ConfigSnapshotError(f"Change plan {plan_id} not found.")
    return plan


def _platform_for_plan(plan: ChangePlan) -> str:
    if plan.plan_type in {"mikrotik_address", "mikrotik_dhcp_server"}:
        return "mikrotik_routeros"
    if plan.plan_type in {"vlan", "cisco_interface_description", "cisco_access_port"}:
        return "cisco_ios"
    raise ConfigSnapshotError(f"Snapshots are not supported for plan type `{plan.plan_type}`.")


def _credential_for_snapshot(device: Device, platform: str) -> DeviceCredential:
    for credential in device.credentials:
        if credential.connection_type == "ssh" and credential.platform_hint == platform:
            return credential
    raise ConfigSnapshotError(f"Saved `{platform}` SSH credentials are required to capture a snapshot.")


def _open_connection(credential: DeviceCredential, platform: str):
    try:
        from netmiko import ConnectHandler
    except ImportError as exc:
        raise ConfigSnapshotError("Netmiko is not installed. Run `pip install -r requirements.txt`.") from exc

    try:
        password = decrypt_secret(credential.encrypted_password)
    except CredentialSecurityError as exc:
        raise ConfigSnapshotError(str(exc)) from exc

    return ConnectHandler(
        device_type=platform,
        host=credential.device.ip_address,
        username=credential.username,
        password=password,
        port=credential.port,
        timeout=10,
        conn_timeout=10,
        auth_timeout=10,
        banner_timeout=10,
    )


def _cisco_interface_from_plan(plan: ChangePlan) -> str | None:
    for line in (plan.proposed_commands or "").splitlines():
        match = re.fullmatch(
            r"interface ((?:Gi|GigabitEthernet|Fa|FastEthernet|Te|TenGigabitEthernet|Eth|Ethernet)\d+(?:/\d+){1,3})",
            line.strip(),
            flags=re.IGNORECASE,
        )
        if match:
            return match.group(1)
    return None
