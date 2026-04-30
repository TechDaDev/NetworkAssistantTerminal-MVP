from __future__ import annotations

import ipaddress
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.database import get_session, init_db
from app.models import Device, DevicePort
from app.safety import UnsafeNetworkError, is_private_cidr
from app.schemas import DeviceFingerprint, HostDiscoveryResult, PortScanResult, ScannedDevice
from app.services.fingerprint import fingerprint_device


COMMON_NMAP_PORTS = "22,23,53,80,443,8080,8443,161,8291,8728,8729,445,139,3389"
ALLOWED_PROFILES: dict[str, list[str]] = {
    "ping": ["-sn"],
    "common-ports": ["-sT", "-Pn", "-p", COMMON_NMAP_PORTS],
    "service-light": ["-sV", "--version-light", "-Pn", "-p", COMMON_NMAP_PORTS],
}


@dataclass
class NmapScanResult:
    target: str
    profile: str
    devices: list[ScannedDevice] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    nmap_path: str | None = None

    @property
    def live_hosts_count(self) -> int:
        return len(self.devices)


def is_nmap_available() -> bool:
    return shutil.which("nmap") is not None


def get_nmap_version() -> str | None:
    path = shutil.which("nmap")
    if not path:
        return None
    try:
        result = subprocess.run(
            [path, "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError, TimeoutError):
        return None
    first_line = (result.stdout or result.stderr or "").splitlines()
    return first_line[0].strip() if first_line else None


def run_nmap_scan(target: str, profile: str) -> NmapScanResult:
    normalized_target = validate_nmap_target(target)
    normalized_profile = validate_nmap_profile(profile)
    path = shutil.which("nmap")
    if not path:
        raise RuntimeError("nmap is not installed. Install it with: sudo apt install nmap")

    started_at = datetime.now(timezone.utc)
    command = [path, *ALLOWED_PROFILES[normalized_profile], normalized_target, "-oX", "-"]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )
    if completed.returncode not in {0, 1}:
        detail = (completed.stderr or completed.stdout or "nmap failed").strip()
        raise RuntimeError(detail)

    result = parse_nmap_xml(completed.stdout)
    result.target = normalized_target
    result.profile = normalized_profile
    result.started_at = started_at
    result.finished_at = datetime.now(timezone.utc)
    result.nmap_path = path
    return result


def parse_nmap_xml(xml_output: str) -> NmapScanResult:
    root = ET.fromstring(xml_output)
    target = "unknown"
    profile = "unknown"
    devices: list[ScannedDevice] = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") not in {None, "up"}:
            continue

        ipv4 = None
        mac = None
        for address in host.findall("address"):
            if address.get("addrtype") == "ipv4":
                ipv4 = address.get("addr")
            elif address.get("addrtype") == "mac":
                mac = address.get("addr")
        if not ipv4:
            continue

        hostname = None
        hostname_node = host.find("./hostnames/hostname")
        if hostname_node is not None:
            hostname = hostname_node.get("name")

        ports: list[PortScanResult] = []
        for port_node in host.findall("./ports/port"):
            state_node = port_node.find("state")
            state = state_node.get("state", "unknown") if state_node is not None else "unknown"
            if state != "open":
                continue
            service = _service_label(port_node.find("service"))
            ports.append(
                PortScanResult(
                    port=int(port_node.get("portid", "0")),
                    protocol=port_node.get("protocol", "tcp"),
                    service_guess=service,
                    state=state,
                )
            )

        host_result = HostDiscoveryResult(ip_address=ipv4, mac_address=mac, hostname=hostname)
        fingerprint = fingerprint_device(host_result, ports)
        if not ports and fingerprint == DeviceFingerprint():
            fingerprint = DeviceFingerprint(notes=["Discovered by nmap host discovery"])
        devices.append(ScannedDevice(host=host_result, ports=ports, fingerprint=fingerprint))

    devices.sort(key=lambda device: ipaddress.ip_address(device.host.ip_address))
    return NmapScanResult(target=target, profile=profile, devices=devices)


def save_nmap_results(result: NmapScanResult) -> None:
    init_db()
    now = datetime.now(timezone.utc)
    with get_session() as session:
        for scanned in result.devices:
            device = session.query(Device).filter(Device.ip_address == scanned.host.ip_address).one_or_none()
            if device is None:
                device = Device(ip_address=scanned.host.ip_address, created_at=now)
                session.add(device)

            device.hostname = scanned.host.hostname or device.hostname
            device.mac_address = scanned.host.mac_address or device.mac_address
            device.vendor_guess = scanned.fingerprint.vendor_guess
            device.device_type_guess = scanned.fingerprint.type_guess
            device.confidence = scanned.fingerprint.confidence
            device.last_seen = now
            device.updated_at = now

            existing = {(port.port, port.protocol): port for port in device.ports}
            seen = {(port.port, port.protocol) for port in scanned.ports}
            for key, saved in list(existing.items()):
                if key not in seen:
                    session.delete(saved)
            for port in scanned.ports:
                saved = existing.get((port.port, port.protocol))
                if saved is None:
                    saved = DevicePort(device=device, port=port.port, protocol=port.protocol)
                    session.add(saved)
                saved.service_guess = port.service_guess
                saved.state = port.state
                saved.last_seen = now
        session.commit()


def validate_nmap_profile(profile: str) -> str:
    normalized = profile.strip().lower().replace("_", "-")
    if normalized == "service light":
        normalized = "service-light"
    if normalized not in ALLOWED_PROFILES:
        allowed = ", ".join(sorted(ALLOWED_PROFILES))
        raise UnsafeNetworkError(f"Unsupported nmap profile `{profile}`. Allowed profiles: {allowed}.")
    return normalized


def validate_nmap_target(target: str) -> str:
    if any(part in target for part in (" ", "\t", "\n")) or target.startswith("-"):
        raise UnsafeNetworkError("Raw nmap arguments are not accepted. Provide only a private IP or private CIDR.")
    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            if network.prefixlen < 24:
                raise UnsafeNetworkError(f"Refusing to scan {network}. Nmap scans are limited to /24 or smaller private CIDRs.")
            if not is_private_cidr(str(network)):
                raise UnsafeNetworkError(f"Refusing to scan {network}. Public targets are blocked.")
            return str(network)
        address = ipaddress.ip_address(target)
    except ValueError as exc:
        raise UnsafeNetworkError("Nmap targets must be private IP addresses or private CIDRs. Hostnames are blocked.") from exc
    if not is_private_cidr(f"{address}/32"):
        raise UnsafeNetworkError(f"Refusing to scan {address}. Public targets are blocked.")
    return str(address)


def _service_label(service_node: ET.Element | None) -> str:
    if service_node is None:
        return "Unknown"
    parts = [service_node.get("name")]
    product = service_node.get("product")
    version = service_node.get("version")
    if product:
        parts.append(product)
    if version:
        parts.append(version)
    return " ".join(part for part in parts if part) or "Unknown"
