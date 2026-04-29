from __future__ import annotations

import ipaddress
import subprocess
import sys
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.database import get_session, init_db
from app.models import Device, ScanRun
from app.safety import is_private_cidr
from app.schemas import DiagnosticFinding, DiagnosticResult
from app.services.network_detection import detect_local_network


MANAGEMENT_PORTS = {
    22: ("SSH", "low"),
    23: ("Telnet", "medium"),
    80: ("HTTP", "low"),
    443: ("HTTPS", "low"),
    8080: ("HTTP alternate", "low"),
    8443: ("HTTPS alternate", "low"),
    161: ("SNMP", "medium"),
    8291: ("MikroTik WinBox", "medium"),
    8728: ("MikroTik API", "medium"),
    8729: ("MikroTik API SSL", "medium"),
    3389: ("RDP", "medium"),
    445: ("SMB", "medium"),
    139: ("NetBIOS", "medium"),
}


class DiagnosticError(ValueError):
    """Raised when a diagnostic target is invalid or unsafe."""


def diagnose_network() -> DiagnosticResult:
    network_info = detect_local_network()
    latest_scan = _latest_scan()
    devices = _devices()
    device_ips = {device.ip_address for device in devices}
    findings: list[DiagnosticFinding] = []
    suggested = ["python main.py report", "python main.py devices"]

    if latest_scan is None:
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="No scan data stored",
                detail="No previous scan was found in SQLite.",
                recommendation="Run `python main.py scan` to collect current local network data.",
            )
        )
        suggested.insert(0, "python main.py scan")
    else:
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="Latest scan available",
                detail=f"Latest scan finished {_format_age(latest_scan.finished_at)}.",
                evidence=[f"CIDR: {latest_scan.cidr}", f"Live hosts: {latest_scan.live_hosts_count}"],
            )
        )

    if network_info.gateway_ip and network_info.gateway_ip not in device_ips:
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="Gateway not present in inventory",
                detail=(
                    f"Gateway {network_info.gateway_ip} is configured but not currently present "
                    "in inventory. This may mean it was not discovered, scan permissions were "
                    "limited, or the latest scan missed it."
                ),
                evidence=[f"Detected gateway: {network_info.gateway_ip}", f"Inventory IPs: {', '.join(sorted(device_ips)) or '--'}"],
                recommendation="Run `python main.py scan` and then `python main.py devices`.",
            )
        )
        suggested.insert(0, "python main.py scan")

    unknown_devices = [
        device for device in devices
        if device.vendor_guess == "Unknown" or device.device_type_guess == "Unknown"
    ]
    if unknown_devices:
        findings.append(
            DiagnosticFinding(
                severity="low",
                title="Some devices need better identification",
                detail=f"{len(unknown_devices)} stored device(s) have unknown vendor or type fields.",
                evidence=[device.ip_address for device in unknown_devices],
                recommendation="Run `python main.py enrich` to collect passive observations.",
            )
        )
        suggested.append("python main.py enrich")

    management_devices = _devices_with_management_ports(devices)
    if management_devices:
        findings.append(
            DiagnosticFinding(
                severity="low",
                title="Possible management/service ports present",
                detail=f"{len(management_devices)} device(s) expose common management or service ports.",
                evidence=[_management_evidence(device) for device in management_devices],
                recommendation="Review `python main.py diagnose management-ports`.",
            )
        )

    if devices and not any(device.observations for device in devices):
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="No enrichment observations stored",
                detail="Stored devices do not yet have enrichment observations.",
                recommendation="Run `python main.py enrich`.",
            )
        )
        suggested.append("python main.py enrich")

    suggested = _dedupe_commands(suggested)
    return DiagnosticResult(
        title="Network Diagnostic Summary",
        summary=(
            f"Local network: {network_info.cidr}; Gateway: {network_info.gateway_ip or '--'}; "
            f"Discovered devices: {len(devices)}"
        ),
        findings=findings,
        suggested_commands=suggested,
    )


def diagnose_device(ip: str) -> DiagnosticResult:
    ip_address = _validate_ip(ip)
    device = _device(str(ip_address))
    if device is None:
        return DiagnosticResult(
            title=f"Device Diagnostic: {ip_address}",
            summary=f"Device {ip_address} is not in inventory.",
            findings=[
                DiagnosticFinding(
                    severity="info",
                    title="Device not found",
                    detail=f"Device {ip_address} is not in inventory.",
                    recommendation="Run `python main.py scan`.",
                )
            ],
            suggested_commands=["python main.py scan", "python main.py devices"],
        )

    findings: list[DiagnosticFinding] = []
    suggested = [f"python main.py device {device.ip_address}", "python main.py enrich"]

    if device.vendor_guess == "Unknown":
        findings.append(
            DiagnosticFinding(
                severity="low",
                title="Vendor is unknown",
                detail="The stored profile does not yet identify a vendor.",
                recommendation="Run `python main.py enrich` or manually correct the profile.",
            )
        )
    if not _latest_observation_value(device, "manual_model") and not _latest_observation_value(device, "model"):
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="Model is unknown",
                detail="No model observation is stored for this device.",
            )
        )

    management_ports = [port for port in device.ports if port.state == "open" and port.port in MANAGEMENT_PORTS]
    if management_ports:
        findings.append(
            DiagnosticFinding(
                severity="low",
                title="Possible management/service ports detected",
                detail="Open ports are not vulnerabilities by themselves, but they may expose admin or service interfaces.",
                evidence=[f"{port.port}/tcp {MANAGEMENT_PORTS[port.port][0]}" for port in management_ports],
                recommendation=f"Review `python main.py device {device.ip_address}`.",
            )
        )

    if not device.credentials:
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="No credentials saved",
                detail="No encrypted SSH credentials are stored for this device.",
                recommendation=f"Only if appropriate, add credentials with `python main.py credentials add {device.ip_address}`.",
            )
        )
        suggested.append(f"python main.py credentials add {device.ip_address}")
    else:
        suggested.append(f"python main.py connect test {device.ip_address}")
        if not device.command_runs:
            findings.append(
                DiagnosticFinding(
                    severity="info",
                    title="No read-only collection history",
                    detail="Credentials exist, but no read-only command collection is stored.",
                    recommendation=f"Run `python main.py connect collect {device.ip_address}`.",
                )
            )
            suggested.append(f"python main.py connect collect {device.ip_address}")

    if _is_stale(device.last_seen):
        findings.append(
            DiagnosticFinding(
                severity="low",
                title="Device data may be stale",
                detail=f"Device was last seen {_format_age(device.last_seen)}.",
                recommendation="Run `python main.py scan` to refresh inventory.",
            )
        )
        suggested.append("python main.py scan")

    summary = (
        f"{device.ip_address}: vendor={device.vendor_guess}, type={device.device_type_guess}, "
        f"confidence={device.confidence}, open_ports={_port_summary(device)}"
    )
    return DiagnosticResult(
        title=f"Device Diagnostic: {device.ip_address}",
        summary=summary,
        findings=findings or [
            DiagnosticFinding(
                severity="info",
                title="No major diagnostic gaps found",
                detail="Stored profile has basic inventory data.",
            )
        ],
        suggested_commands=_dedupe_commands(suggested),
    )


def diagnose_management_ports() -> DiagnosticResult:
    devices = _devices()
    findings: list[DiagnosticFinding] = []
    suggested = ["python main.py devices", "python main.py enrich"]

    for device in devices:
        for port in sorted(device.ports, key=lambda item: item.port):
            if port.state != "open" or port.port not in MANAGEMENT_PORTS:
                continue
            label, base_severity = MANAGEMENT_PORTS[port.port]
            severity = base_severity
            if port.port in {80, 443, 8080, 8443} and "Router" in device.device_type_guess:
                severity = "medium"
            findings.append(
                DiagnosticFinding(
                    severity=severity,
                    title="Possible management/service port detected",
                    detail=f"{device.ip_address} has {port.port}/tcp open ({label}). This is not automatically a vulnerability.",
                    evidence=[
                        f"Device type guess: {device.device_type_guess}",
                        f"Service guess: {port.service_guess}",
                    ],
                    recommendation=f"Review `python main.py device {device.ip_address}`.",
                )
            )
            suggested.append(f"python main.py device {device.ip_address}")
            if device.credentials:
                suggested.append(f"python main.py connect collect {device.ip_address}")

    if not findings:
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="No common management/service ports found",
                detail="No stored device ports matched the Phase 5 management/service watchlist.",
            )
        )

    return DiagnosticResult(
        title="Management Ports Diagnostic",
        summary=f"Checked {len(devices)} stored device(s) for common management/service ports.",
        findings=findings,
        suggested_commands=_dedupe_commands(suggested),
    )


def diagnose_connectivity(target_ip: str) -> DiagnosticResult:
    ip_address = _validate_ip(target_ip)
    if not is_private_cidr(f"{ip_address}/32"):
        raise DiagnosticError("Public IP connectivity diagnostics are blocked in Phase 5.")

    network_info = detect_local_network()
    network = ipaddress.ip_network(network_info.cidr, strict=False)
    in_local_cidr = ip_address in network
    device = _device(str(ip_address))
    ping_success, ping_detail = _ping(str(ip_address))
    is_gateway = network_info.gateway_ip == str(ip_address)

    findings: list[DiagnosticFinding] = [
        DiagnosticFinding(
            severity="info",
            title="Target validation",
            detail=f"Target {ip_address} is private and {'inside' if in_local_cidr else 'outside'} detected local CIDR {network_info.cidr}.",
            evidence=[f"Detected local network: {network_info.cidr}"],
        )
    ]
    if is_gateway:
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="Target matches configured gateway",
                detail=f"{ip_address} matches the detected default gateway.",
            )
        )
    if ping_success:
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="Ping succeeded",
                detail="The target replied to a single safe ping check.",
                evidence=[ping_detail],
            )
        )
    else:
        findings.append(
            DiagnosticFinding(
                severity="low",
                title="Ping failed or was blocked",
                detail="The target did not reply to a single ping check. This does not prove the device is offline because ping may be blocked.",
                evidence=[ping_detail],
            )
        )

    suggested = ["python main.py scan", "python main.py enrich"]
    if device:
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="Target exists in inventory",
                detail=f"Known ports: {_port_summary(device)}",
                evidence=[f"Last seen: {device.last_seen}"],
                recommendation=f"Review `python main.py device {device.ip_address}`.",
            )
        )
        suggested.insert(1, f"python main.py device {device.ip_address}")
    else:
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="Target not in inventory",
                detail="No stored inventory profile exists for this target.",
                recommendation="Run `python main.py scan` to refresh local discovery.",
            )
        )

    return DiagnosticResult(
        title=f"Connectivity Diagnostic: {ip_address}",
        summary=(
            f"Target {ip_address}; local CIDR={network_info.cidr}; "
            f"gateway_match={'yes' if is_gateway else 'no'}; ping={'success' if ping_success else 'failed or blocked'}"
        ),
        findings=findings,
        suggested_commands=_dedupe_commands(suggested),
    )


def _latest_scan() -> ScanRun | None:
    init_db()
    with get_session() as session:
        return session.scalar(select(ScanRun).order_by(ScanRun.finished_at.desc()))


def _devices() -> list[Device]:
    init_db()
    with get_session() as session:
        return list(
            session.scalars(
                select(Device)
                .options(
                    selectinload(Device.ports),
                    selectinload(Device.observations),
                    selectinload(Device.credentials),
                    selectinload(Device.command_runs),
                )
                .order_by(Device.ip_address)
            ).all()
        )


def _device(ip_address: str) -> Device | None:
    init_db()
    with get_session() as session:
        return session.scalar(
            select(Device)
            .options(
                selectinload(Device.ports),
                selectinload(Device.observations),
                selectinload(Device.credentials),
                selectinload(Device.command_runs),
            )
            .where(Device.ip_address == ip_address)
        )


def _validate_ip(ip_address: str) -> ipaddress.IPv4Address:
    try:
        parsed = ipaddress.ip_address(ip_address)
    except ValueError as exc:
        raise DiagnosticError(f"Invalid IP address: {ip_address}") from exc
    if parsed.version != 4:
        raise DiagnosticError("Only IPv4 diagnostics are supported in Phase 5.")
    return parsed


def _ping_command(ip_address: str) -> list[str]:
    if sys.platform.startswith("win"):
        return ["ping", "-n", "1", "-w", "1000", ip_address]
    return ["ping", "-c", "1", "-W", "1", ip_address]


def _ping(ip_address: str) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            _ping_command(ip_address),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
    except (FileNotFoundError, subprocess.SubprocessError, TimeoutError) as exc:
        return False, f"Ping command failed to run: {exc}"
    if result.returncode == 0:
        return True, "Ping returned success."
    return False, f"Ping exited with code {result.returncode}."


def _devices_with_management_ports(devices: list[Device]) -> list[Device]:
    return [
        device for device in devices
        if any(port.state == "open" and port.port in MANAGEMENT_PORTS for port in device.ports)
    ]


def _management_evidence(device: Device) -> str:
    ports = [
        f"{port.port}/{port.protocol} {MANAGEMENT_PORTS[port.port][0]}"
        for port in sorted(device.ports, key=lambda item: item.port)
        if port.state == "open" and port.port in MANAGEMENT_PORTS
    ]
    return f"{device.ip_address}: {', '.join(ports)}"


def _port_summary(device: Device) -> str:
    ports = [
        f"{port.port}/{port.protocol} {port.service_guess}"
        for port in sorted(device.ports, key=lambda item: item.port)
        if port.state == "open"
    ]
    return ", ".join(ports) if ports else "--"


def _latest_observation_value(device: Device, observation_type: str) -> str | None:
    matches = [
        observation for observation in device.observations
        if observation.observation_type == observation_type
    ]
    if not matches:
        return None
    return max(matches, key=lambda item: item.created_at).observation_value


def _is_stale(value: datetime) -> bool:
    age = datetime.now(timezone.utc) - _as_utc(value)
    return age.days >= 7


def _format_age(value: datetime) -> str:
    age = datetime.now(timezone.utc) - _as_utc(value)
    if age.days:
        return f"{age.days} day(s) ago"
    hours = age.seconds // 3600
    if hours:
        return f"{hours} hour(s) ago"
    minutes = age.seconds // 60
    return f"{minutes} minute(s) ago"


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _dedupe_commands(commands: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for command in commands:
        if command not in seen:
            seen.add(command)
            result.append(command)
    return result
