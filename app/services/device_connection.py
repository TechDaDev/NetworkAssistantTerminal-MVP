from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.command_policy import (
    CommandPolicyError,
    collection_commands_for,
    is_sensitive_readonly_command,
    normalize_command,
    reject_dangerous_patterns,
    validate_readonly_command,
)
from app.database import get_session, init_db
from app.models import CommandRun, Device, DeviceConfigSnapshot, DeviceCredential, DeviceObservation
from app.services.security import CredentialSecurityError, decrypt_secret


PLATFORM_TO_NETMIKO = {
    "cisco_ios": "cisco_ios",
    "mikrotik_routeros": "mikrotik_routeros",
    "linux": "linux",
}


@dataclass
class ConnectionTestResult:
    ip_address: str
    success: bool
    platform: str
    message: str


@dataclass
class CommandResult:
    ip_address: str
    command: str
    output: str
    success: bool
    error_message: str | None
    started_at: datetime
    finished_at: datetime
    sensitive: bool = False


@dataclass
class DeviceProfileCollectionResult:
    ip_address: str
    platform: str
    command_results: list[CommandResult] = field(default_factory=list)

    @property
    def success_count(self) -> int:
        return sum(1 for result in self.command_results if result.success)

    @property
    def failure_count(self) -> int:
        return sum(1 for result in self.command_results if not result.success)


class DeviceConnectionError(RuntimeError):
    """Raised when a stored device cannot be connected to safely."""


def test_connection(ip_address: str) -> ConnectionTestResult:
    credential = _credential_for_ip(ip_address)
    platform = _resolve_platform(credential)
    try:
        connection = _open_connection(credential, platform)
        connection.disconnect()
    except Exception as exc:  # Netmiko raises several connection/auth exceptions.
        _update_credential_status(credential.id, "failed")
        return ConnectionTestResult(
            ip_address=ip_address,
            success=False,
            platform=platform,
            message=str(exc),
        )

    _update_credential_status(credential.id, "success", platform_hint=platform)
    return ConnectionTestResult(
        ip_address=ip_address,
        success=True,
        platform=platform,
        message="SSH login succeeded.",
    )


def run_readonly_command(ip_address: str, command: str) -> CommandResult:
    reject_dangerous_patterns(command)
    credential = _credential_for_ip(ip_address)
    platform = _resolve_platform(credential)
    normalized = normalize_command(command)
    validate_readonly_command(platform, normalized)

    started_at = datetime.now(timezone.utc)
    output = ""
    error_message = None
    success = False
    try:
        connection = _open_connection(credential, platform)
        try:
            output = connection.send_command(normalized, read_timeout=20)
            success = True
        finally:
            connection.disconnect()
    except Exception as exc:  # Netmiko may raise auth, timeout, or channel errors.
        error_message = str(exc)
    finished_at = datetime.now(timezone.utc)

    result = CommandResult(
        ip_address=ip_address,
        command=normalized,
        output=output,
        success=success,
        error_message=error_message,
        started_at=started_at,
        finished_at=finished_at,
        sensitive=is_sensitive_readonly_command(normalized),
    )
    _save_command_result(credential.device_id, platform, result)
    if success:
        _update_credential_status(credential.id, "success", platform_hint=platform)
    else:
        _update_credential_status(credential.id, "failed")
    return result


def run_readonly_profile_collection(ip_address: str) -> DeviceProfileCollectionResult:
    credential = _credential_for_ip(ip_address)
    platform = _resolve_platform(credential)
    commands = collection_commands_for(platform)
    results = [run_readonly_command(ip_address, command) for command in commands]
    return DeviceProfileCollectionResult(
        ip_address=ip_address,
        platform=platform,
        command_results=results,
    )


def command_history(ip_address: str, limit: int = 25) -> list[CommandRun]:
    init_db()
    with get_session() as session:
        return list(
            session.scalars(
                select(CommandRun)
                .join(Device)
                .where(Device.ip_address == ip_address)
                .order_by(CommandRun.started_at.desc())
                .limit(limit)
            ).all()
        )


def _credential_for_ip(ip_address: str) -> DeviceCredential:
    init_db()
    with get_session() as session:
        credential = session.scalar(
            select(DeviceCredential)
            .join(Device)
            .options(selectinload(DeviceCredential.device))
            .where(Device.ip_address == ip_address, DeviceCredential.connection_type == "ssh")
        )
        if credential is None:
            raise DeviceConnectionError("No SSH credentials stored for this device.")
        return credential


def _resolve_platform(credential: DeviceCredential) -> str:
    if credential.platform_hint != "unknown_ssh":
        return credential.platform_hint
    detected = _autodetect_platform(credential)
    if detected:
        return detected
    raise DeviceConnectionError(
        "Platform is `unknown_ssh` and autodetection failed. Update credentials with "
        "a platform hint: cisco_ios, mikrotik_routeros, or linux."
    )


def _autodetect_platform(credential: DeviceCredential) -> str | None:
    try:
        from netmiko import SSHDetect
    except ImportError as exc:
        raise DeviceConnectionError("Netmiko is not installed. Run `pip install -r requirements.txt`.") from exc

    password = decrypt_secret(credential.encrypted_password)
    params = {
        "device_type": "autodetect",
        "host": credential.device.ip_address,
        "username": credential.username,
        "password": password,
        "port": credential.port,
        "timeout": 10,
        "conn_timeout": 10,
    }
    try:
        detected = SSHDetect(**params).autodetect()
    except Exception:
        return None
    if detected in PLATFORM_TO_NETMIKO.values():
        for platform, netmiko_type in PLATFORM_TO_NETMIKO.items():
            if netmiko_type == detected:
                return platform
    return None


def _open_connection(credential: DeviceCredential, platform: str):
    try:
        from netmiko import ConnectHandler
    except ImportError as exc:
        raise DeviceConnectionError("Netmiko is not installed. Run `pip install -r requirements.txt`.") from exc

    netmiko_type = PLATFORM_TO_NETMIKO.get(platform)
    if netmiko_type is None:
        raise DeviceConnectionError(f"Unsupported SSH platform `{platform}`.")

    try:
        password = decrypt_secret(credential.encrypted_password)
    except CredentialSecurityError:
        raise

    return ConnectHandler(
        device_type=netmiko_type,
        host=credential.device.ip_address,
        username=credential.username,
        password=password,
        port=credential.port,
        timeout=10,
        conn_timeout=10,
        auth_timeout=10,
        banner_timeout=10,
    )


def _update_credential_status(
    credential_id: int,
    status: str,
    platform_hint: str | None = None,
) -> None:
    now = datetime.now(timezone.utc)
    with get_session() as session:
        credential = session.get(DeviceCredential, credential_id)
        if credential is None:
            return
        credential.status = status
        credential.updated_at = now
        if status == "success":
            credential.last_success_at = now
        if platform_hint and credential.platform_hint == "unknown_ssh":
            credential.platform_hint = platform_hint
        session.commit()


def _save_command_result(device_id: int, platform: str, result: CommandResult) -> None:
    with get_session() as session:
        device = session.get(Device, device_id)
        if device is None:
            return
        command_run = CommandRun(
            device=device,
            command=result.command,
            output=result.output,
            success=result.success,
            error_message=result.error_message,
            started_at=result.started_at,
            finished_at=result.finished_at,
        )
        session.add(command_run)

        if result.success:
            _add_command_observations(device, platform, result.command, result.output)
            if result.sensitive:
                session.add(
                    DeviceConfigSnapshot(
                        device=device,
                        snapshot_type=result.command,
                        content=result.output,
                    )
                )
        session.commit()


def _add_observation(
    device: Device,
    observation_type: str,
    observation_value: str,
    source: str,
    confidence: str = "Medium",
) -> None:
    value = observation_value.strip()
    if not value:
        return
    if any(
        observation.observation_type == observation_type
        and observation.observation_value == value
        and observation.source == source
        for observation in device.observations
    ):
        return
    device.observations.append(
        DeviceObservation(
            observation_type=observation_type,
            observation_value=value,
            source=source,
            confidence=confidence,
        )
    )


def _add_command_observations(device: Device, platform: str, command: str, output: str) -> None:
    if platform == "mikrotik_routeros":
        _add_mikrotik_observations(device, command, output)
    elif platform == "cisco_ios":
        _add_cisco_observations(device, command, output)
    elif platform == "linux":
        _add_linux_observations(device, command, output)


def _add_mikrotik_observations(device: Device, command: str, output: str) -> None:
    if command == "/system identity print":
        match = re.search(r"name:\s*(.+)", output)
        if match:
            _add_observation(device, "device_identity", match.group(1), command, "High")
    if command == "/system resource print":
        version = re.search(r"version:\s*(.+)", output)
        board = re.search(r"board-name:\s*(.+)", output)
        if version:
            _add_observation(device, "os_version", version.group(1), command, "High")
        if board:
            _add_observation(device, "model", board.group(1), command, "High")
        device.vendor_guess = "MikroTik"
        device.device_type_guess = "Router"
        device.confidence = "High"


def _add_cisco_observations(device: Device, command: str, output: str) -> None:
    if command == "show version":
        version_line = next((line.strip() for line in output.splitlines() if "Version" in line), "")
        model_match = re.search(r"[Cc]isco\s+(\S+)", output)
        if version_line:
            _add_observation(device, "os_version", version_line, command, "High")
        if model_match:
            _add_observation(device, "model", model_match.group(1), command, "Medium")
        device.vendor_guess = "Cisco"
        device.device_type_guess = "Router/Switch"
        device.confidence = "High"


def _add_linux_observations(device: Device, command: str, output: str) -> None:
    if command == "hostname":
        _add_observation(device, "hostname", output.splitlines()[0] if output.splitlines() else output, command, "High")
    if command == "uname -a":
        _add_observation(device, "os_version", output.splitlines()[0] if output.splitlines() else output, command, "Medium")
