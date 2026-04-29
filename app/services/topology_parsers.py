from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class NeighborRecord:
    name: str
    local_interface: str | None = None
    neighbor_interface: str | None = None
    management_ip: str | None = None
    platform: str | None = None


@dataclass(frozen=True)
class ArpRecord:
    ip_address: str
    mac_address: str | None = None
    interface: str | None = None


def parse_cisco_cdp_neighbors(output: str) -> list[NeighborRecord]:
    records: list[NeighborRecord] = []
    blocks = re.split(r"-{5,}|\n\s*\n(?=Device ID:)", output)
    for block in blocks:
        if "Device ID:" not in block:
            continue
        name = _search(r"Device ID:\s*(.+)", block)
        if not name:
            continue
        records.append(
            NeighborRecord(
                name=name,
                local_interface=_search(r"Interface:\s*([^,\n]+)", block),
                neighbor_interface=_search(r"Port ID(?: \(outgoing port\))?:\s*(.+)", block),
                management_ip=_search(r"(?:IP address|IPv4 Address):\s*([0-9.]+)", block),
                platform=_search(r"Platform:\s*([^,\n]+)", block),
            )
        )
    return records


def parse_cisco_lldp_neighbors(output: str) -> list[NeighborRecord]:
    records: list[NeighborRecord] = []
    blocks = re.split(r"-{5,}|\n\s*\n(?=(?:Chassis id|System Name|Local Intf):)", output, flags=re.IGNORECASE)
    for block in blocks:
        if not re.search(r"(System Name|Local Intf|Port id):", block, re.IGNORECASE):
            continue
        name = _search(r"System Name:\s*(.+)", block) or _search(r"Chassis id:\s*(.+)", block)
        if not name:
            continue
        records.append(
            NeighborRecord(
                name=name,
                local_interface=_search(r"Local Intf:\s*(.+)", block) or _search(r"Local Interface:\s*(.+)", block),
                neighbor_interface=_search(r"Port id:\s*(.+)", block) or _search(r"Port ID:\s*(.+)", block),
                management_ip=_search(r"Management Address:\s*([0-9.]+)", block),
                platform=_search(r"System Description:\s*(.+)", block),
            )
        )
    if not records:
        records.extend(_parse_lldp_table(output))
    return records


def parse_mikrotik_arp(output: str) -> list[ArpRecord]:
    records: list[ArpRecord] = []
    for line in output.splitlines():
        if not re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line):
            continue
        ip = _search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
        mac = _search(r"\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b", line)
        iface = _search(r"(?:interface=)?([A-Za-z][A-Za-z0-9_.\-/]+)\s*$", line)
        if ip:
            records.append(ArpRecord(ip_address=ip, mac_address=mac, interface=iface))
    return records


def _parse_lldp_table(output: str) -> list[NeighborRecord]:
    records: list[NeighborRecord] = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 4 and not line.lower().startswith(("device", "local", "capability")):
            if re.search(r"[A-Za-z]", parts[0]) and re.search(r"\d", parts[1]):
                records.append(
                    NeighborRecord(
                        name=parts[0],
                        local_interface=parts[1],
                        neighbor_interface=parts[-1],
                    )
                )
    return records


def _search(pattern: str, text: str) -> str | None:
    match = re.search(pattern, text, flags=re.IGNORECASE)
    if not match:
        return None
    value = match.group(1).strip()
    return value or None
