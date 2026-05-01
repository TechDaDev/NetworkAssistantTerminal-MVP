"""answer_network_fact — low-risk local-only network fact Q&A.

Answers questions about the local gateway, network, and interface from
network detection + inventory. No LLM, no SSH, no subprocess.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.services.inventory import get_device_profile
from app.services.network_detection import detect_local_network


@dataclass
class NetworkFactResult:
    gateway_ip: str | None = None
    vendor: str | None = None
    device_type: str | None = None
    open_ports: list[int] = field(default_factory=list)
    local_ip: str | None = None
    interface: str | None = None
    network: str | None = None
    cidr: str | None = None
    in_inventory: bool = False
    evidence: list[str] = field(default_factory=list)
    note: str | None = None
    suggest_scan: bool = False

    def as_dict(self) -> dict:
        return {
            "gateway_ip": self.gateway_ip,
            "vendor": self.vendor,
            "device_type": self.device_type,
            "open_ports": self.open_ports,
            "local_ip": self.local_ip,
            "interface": self.interface,
            "network": self.network,
            "cidr": self.cidr,
            "in_inventory": self.in_inventory,
            "evidence": self.evidence,
            "note": self.note,
            "suggest_scan": self.suggest_scan,
        }


def answer_network_fact(question: str | None = None) -> NetworkFactResult:
    """Answer a local network fact question from detection + inventory.

    Returns a NetworkFactResult. Never calls LLM/SSH/subprocess.
    """
    result = NetworkFactResult()

    try:
        network = detect_local_network()
        result.local_ip = network.local_ip
        result.interface = network.interface_name
        result.cidr = network.cidr
        result.network = network.cidr
        result.gateway_ip = network.gateway_ip
        result.evidence.append("Local gateway detected from default route.")
    except Exception:
        result.note = "Could not detect local network. Check your network interface."
        return result

    if not result.gateway_ip:
        result.note = "No default gateway was detected on this host."
        return result

    device = get_device_profile(result.gateway_ip)
    if device is not None:
        result.in_inventory = True
        result.vendor = device.vendor_guess or "Unknown"
        result.device_type = device.device_type_guess or "Unknown"
        result.open_ports = [port.port for port in (device.ports or [])]
        result.evidence.append("Inventory has a matching device record.")
        if result.open_ports:
            result.evidence.append(f"Open ports from last scan: {', '.join(str(p) for p in result.open_ports)}.")
    else:
        result.vendor = None
        result.device_type = None
        result.suggest_scan = True
        result.note = (
            "The gateway is not in inventory yet.\n"
            "I can scan/enrich the local network to identify it."
        )

    # For port-specific questions mention if we have them or what to do
    q = (question or "").lower()
    if any(kw in q for kw in ("port", "ports", "open ports")):
        if not result.open_ports:
            result.note = (
                "No port data available for the gateway. "
                "Try: scan my network / nmap scan " + (result.gateway_ip or "gateway")
            )

    return result
