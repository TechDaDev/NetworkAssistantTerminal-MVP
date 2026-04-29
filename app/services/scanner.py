from __future__ import annotations

import ipaddress
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from app.config import settings
from app.schemas import HostDiscoveryResult, PortScanResult, ScanResult, ScannedDevice
from app.services.fingerprint import fingerprint_device
from app.services.network_detection import detect_local_network


COMMON_PORTS: dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP alternate",
    8443: "HTTPS alternate",
    161: "SNMP",
    8291: "MikroTik WinBox",
    8728: "MikroTik API",
    8729: "MikroTik API SSL",
    445: "SMB",
    139: "NetBIOS",
    3389: "RDP",
}


def _hostname_for_ip(ip_address: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except (socket.herror, socket.gaierror, TimeoutError):
        return None


def _discover_with_scapy(cidr: str) -> list[HostDiscoveryResult]:
    from scapy.all import ARP, Ether, srp  # type: ignore

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    answered, _ = srp(packet, timeout=settings.discovery_timeout_seconds, verbose=False)
    hosts: list[HostDiscoveryResult] = []
    for _, received in answered:
        ip_address = received.psrc
        hosts.append(
            HostDiscoveryResult(
                ip_address=ip_address,
                mac_address=received.hwsrc,
                hostname=_hostname_for_ip(ip_address),
            )
        )
    return sorted(hosts, key=lambda host: ipaddress.ip_address(host.ip_address))


def _ping_command(ip_address: str) -> list[str]:
    if sys.platform.startswith("win"):
        return ["ping", "-n", "1", "-w", "800", ip_address]
    return ["ping", "-c", "1", "-W", "1", ip_address]


def _host_responds(ip_address: str) -> bool:
    try:
        result = subprocess.run(
            _ping_command(ip_address),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
        if result.returncode == 0:
            return True
    except (FileNotFoundError, subprocess.SubprocessError, TimeoutError):
        pass

    for port in (80, 443, 22, 445):
        try:
            with socket.create_connection(
                (ip_address, port), timeout=settings.port_scan_timeout_seconds
            ):
                return True
        except OSError:
            continue
    return False


def _discover_with_fallback(cidr: str) -> list[HostDiscoveryResult]:
    network = ipaddress.ip_network(cidr, strict=False)
    hosts: list[HostDiscoveryResult] = []
    with ThreadPoolExecutor(max_workers=64) as executor:
        futures = {
            executor.submit(_host_responds, str(ip_address)): str(ip_address)
            for ip_address in network.hosts()
        }
        for future in as_completed(futures):
            ip_address = futures[future]
            try:
                if future.result():
                    hosts.append(
                        HostDiscoveryResult(
                            ip_address=ip_address,
                            hostname=_hostname_for_ip(ip_address),
                        )
                    )
            except OSError:
                continue
    return sorted(hosts, key=lambda host: ipaddress.ip_address(host.ip_address))


def discover_live_hosts(cidr: str) -> list[HostDiscoveryResult]:
    try:
        hosts = _discover_with_scapy(cidr)
        if hosts:
            return hosts
    except (ImportError, PermissionError, OSError):
        pass
    return _discover_with_fallback(cidr)


def scan_common_ports(ip: str, ports: list[int] | None = None) -> list[PortScanResult]:
    ports_to_scan = ports or list(COMMON_PORTS)
    open_ports: list[PortScanResult] = []
    for port in ports_to_scan:
        try:
            with socket.create_connection((ip, port), timeout=settings.port_scan_timeout_seconds):
                open_ports.append(
                    PortScanResult(
                        port=port,
                        service_guess=COMMON_PORTS.get(port, "Unknown"),
                    )
                )
        except OSError:
            continue
    return open_ports


def scan_network(cidr: str) -> ScanResult:
    network_info = detect_local_network()
    started_at = datetime.now(timezone.utc)
    hosts = discover_live_hosts(cidr)
    devices: list[ScannedDevice] = []

    with ThreadPoolExecutor(max_workers=32) as executor:
        futures = {
            executor.submit(scan_common_ports, host.ip_address, list(COMMON_PORTS)): host
            for host in hosts
        }
        for future in as_completed(futures):
            host = futures[future]
            ports = future.result()
            fingerprint = fingerprint_device(host, ports, gateway_ip=network_info.gateway_ip)
            devices.append(ScannedDevice(host=host, ports=ports, fingerprint=fingerprint))

    devices.sort(key=lambda device: ipaddress.ip_address(device.host.ip_address))
    return ScanResult(
        network_info=network_info,
        devices=devices,
        started_at=started_at,
        finished_at=datetime.now(timezone.utc),
    )
