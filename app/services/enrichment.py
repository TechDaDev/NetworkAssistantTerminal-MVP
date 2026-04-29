from __future__ import annotations

import re
import socket
import ssl
from html.parser import HTMLParser

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.config import settings
from app.database import get_session, init_db
from app.models import Device, DeviceObservation
from app.services.network_detection import detect_local_network


OUI_VENDOR_PREFIXES = {
    "00:0C:42": "MikroTik",
    "18:FD:74": "MikroTik",
    "2C:C8:1B": "Routerboard.com",
    "48:8F:5A": "MikroTik",
    "64:D1:54": "Routerboard.com",
    "74:4D:28": "Routerboard.com",
    "D4:CA:6D": "Routerboard.com",
    "E4:8D:8C": "Routerboard.com",
    "F4:1E:57": "MikroTik",
    "00:1A:79": "Cisco",
    "00:1B:54": "Cisco",
    "00:25:9C": "Cisco",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
}


class _TitleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_title = False
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.parts.append(data.strip())

    @property
    def title(self) -> str | None:
        title = " ".join(part for part in self.parts if part)
        return re.sub(r"\s+", " ", title).strip() or None


def lookup_mac_vendor(mac_address: str | None) -> str | None:
    if not mac_address:
        return None
    normalized = mac_address.upper().replace("-", ":")
    prefix = ":".join(normalized.split(":")[:3])
    return OUI_VENDOR_PREFIXES.get(prefix)


def grab_http_title(ip_address: str, port: int, use_tls: bool = False) -> str | None:
    request = f"GET / HTTP/1.0\r\nHost: {ip_address}\r\nUser-Agent: NetworkAssistant/2\r\n\r\n"
    try:
        raw_socket = socket.create_connection(
            (ip_address, port), timeout=settings.port_scan_timeout_seconds
        )
        with raw_socket:
            if use_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with context.wrap_socket(raw_socket, server_hostname=ip_address) as tls_socket:
                    tls_socket.settimeout(settings.port_scan_timeout_seconds)
                    tls_socket.sendall(request.encode("ascii"))
                    data = tls_socket.recv(4096)
            else:
                raw_socket.settimeout(settings.port_scan_timeout_seconds)
                raw_socket.sendall(request.encode("ascii"))
                data = raw_socket.recv(4096)
    except OSError:
        return None

    parser = _TitleParser()
    try:
        parser.feed(data.decode("utf-8", errors="ignore"))
    except ValueError:
        return None
    return parser.title


def grab_ssh_banner(ip_address: str, port: int = 22) -> str | None:
    try:
        with socket.create_connection(
            (ip_address, port), timeout=settings.port_scan_timeout_seconds
        ) as sock:
            sock.settimeout(settings.port_scan_timeout_seconds)
            banner = sock.recv(255).decode("utf-8", errors="ignore").strip()
    except OSError:
        return None
    return banner if banner.startswith("SSH-") else None


def detect_snmp_lightweight(ip_address: str, has_snmp_port: bool) -> str | None:
    if not has_snmp_port:
        return None
    return "SNMP port detected; no community strings or authenticated queries attempted"


def _add_observation(
    device: Device,
    observation_type: str,
    observation_value: str | bool,
    source: str,
    confidence: str,
) -> None:
    value = str(observation_value).lower() if isinstance(observation_value, bool) else str(observation_value)
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


def enrich_stored_devices() -> list[Device]:
    init_db()
    network_info = detect_local_network()
    with get_session() as session:
        devices = session.scalars(
            select(Device)
            .options(selectinload(Device.ports), selectinload(Device.observations))
            .order_by(Device.ip_address)
        ).all()

        for device in devices:
            mac_vendor = lookup_mac_vendor(device.mac_address)
            if mac_vendor:
                _add_observation(device, "mac_vendor", mac_vendor, "oui_lookup", "Medium")
                if device.vendor_guess == "Unknown":
                    device.vendor_guess = mac_vendor
                    device.confidence = "Medium"

            if network_info.gateway_ip and device.ip_address == network_info.gateway_ip:
                _add_observation(device, "gateway", True, "network_detection", "High")
                device.device_type_guess = "Router/Gateway"
                device.confidence = "High"

            if device.hostname:
                _add_observation(device, "hostname", device.hostname, "reverse_dns", "Medium")

            open_ports = {port.port for port in device.ports if port.state == "open"}
            for port in sorted(open_ports.intersection({80, 8080})):
                title = grab_http_title(device.ip_address, port, use_tls=False)
                if title:
                    _add_observation(device, "http_title", title, f"http:{port}", "Medium")
                    _apply_title_hints(device, title)

            for port in sorted(open_ports.intersection({443, 8443})):
                title = grab_http_title(device.ip_address, port, use_tls=True)
                if title:
                    _add_observation(device, "http_title", title, f"https:{port}", "Medium")
                    _apply_title_hints(device, title)

            if 22 in open_ports:
                banner = grab_ssh_banner(device.ip_address)
                if banner:
                    _add_observation(device, "ssh_banner", banner, "ssh_banner", "Medium")
                    _apply_banner_hints(device, banner)

            snmp_note = detect_snmp_lightweight(device.ip_address, 161 in open_ports)
            if snmp_note:
                _add_observation(device, "snmp_detection", snmp_note, "port_scan", "Low")

        session.commit()

        return list(
            session.scalars(
                select(Device)
                .options(selectinload(Device.ports), selectinload(Device.observations))
                .order_by(Device.ip_address)
            ).all()
        )


def _apply_title_hints(device: Device, title: str) -> None:
    lowered = title.lower()
    if "mikrotik" in lowered or "routeros" in lowered or "webfig" in lowered:
        device.vendor_guess = "MikroTik"
        device.device_type_guess = "Router"
        device.confidence = "High"
    elif any(term in lowered for term in ("router", "gateway", "switch", "access point", "ap ")):
        if device.device_type_guess == "Unknown":
            device.device_type_guess = "Network Device"
        if device.confidence == "Low":
            device.confidence = "Medium"


def _apply_banner_hints(device: Device, banner: str) -> None:
    lowered = banner.lower()
    if "rosssh" in lowered or "routeros" in lowered:
        device.vendor_guess = "MikroTik"
        device.device_type_guess = "Router"
        device.confidence = "High"
