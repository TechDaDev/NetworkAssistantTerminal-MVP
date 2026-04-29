from __future__ import annotations

import ipaddress
from pathlib import Path

import netifaces
import psutil

from app.safety import is_private_cidr, is_scan_size_allowed
from app.schemas import NetworkInfo


class NetworkDetectionError(RuntimeError):
    """Raised when local network information cannot be detected."""


def _prefix_from_netmask(netmask: str) -> int:
    return ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen


def _mac_for_interface(interface_name: str) -> str | None:
    for address in psutil.net_if_addrs().get(interface_name, []):
        if getattr(address, "family", None) == psutil.AF_LINK:
            return address.address
    try:
        link_addresses = netifaces.ifaddresses(interface_name).get(netifaces.AF_LINK, [])
        return link_addresses[0].get("addr") if link_addresses else None
    except (ValueError, KeyError):
        return None


def _default_gateway() -> tuple[str | None, str | None]:
    try:
        gateways = netifaces.gateways()
        default = gateways.get("default", {}).get(netifaces.AF_INET)
        if default:
            gateway_ip, interface_name = default[0], default[1]
            return gateway_ip, interface_name
    except (OSError, PermissionError):
        pass

    route_file = Path("/proc/net/route")
    if route_file.exists():
        try:
            for line in route_file.read_text(encoding="utf-8").splitlines()[1:]:
                fields = line.split()
                if len(fields) >= 3 and fields[1] == "00000000":
                    interface_name = fields[0]
                    gateway_hex = fields[2]
                    gateway_ip = str(
                        ipaddress.IPv4Address(bytes.fromhex(gateway_hex)[::-1])
                    )
                    return gateway_ip, interface_name
        except (OSError, ValueError):
            pass

    return None, None


def detect_local_network() -> NetworkInfo:
    gateway_ip, interface_name = _default_gateway()
    if not interface_name:
        raise NetworkDetectionError("Could not detect a default IPv4 network interface.")

    addresses = netifaces.ifaddresses(interface_name).get(netifaces.AF_INET, [])
    if not addresses:
        raise NetworkDetectionError(f"Interface {interface_name} has no IPv4 address.")

    selected = next((addr for addr in addresses if "addr" in addr and "netmask" in addr), None)
    if not selected:
        raise NetworkDetectionError(f"Interface {interface_name} has no usable IPv4/netmask pair.")

    local_ip = selected["addr"]
    netmask = selected["netmask"]
    prefix_length = _prefix_from_netmask(netmask)
    network = ipaddress.ip_network(f"{local_ip}/{prefix_length}", strict=False)
    cidr = str(network)
    private = is_private_cidr(cidr)
    safe_to_scan = private and is_scan_size_allowed(cidr)

    return NetworkInfo(
        interface_name=interface_name,
        local_ip=local_ip,
        netmask=netmask,
        cidr=cidr,
        gateway_ip=gateway_ip,
        mac_address=_mac_for_interface(interface_name),
        is_private=private,
        prefix_length=prefix_length,
        safe_to_scan=safe_to_scan,
    )
