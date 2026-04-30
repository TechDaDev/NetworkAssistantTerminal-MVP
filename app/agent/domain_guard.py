from __future__ import annotations

import re

from pydantic import BaseModel


NETWORK_ONLY_MESSAGE = (
    "This agent is specialized for local network operations. I can help with routers, "
    "switches, topology, scanning, diagnostics, backups, and controlled configuration workflows."
)


class DomainDecision(BaseModel):
    is_network_related: bool
    reason: str
    category: str | None = None


ALLOW_TERMS = {
    "router", "switch", "firewall", "access point", "gateway", "lan", "wan", "vlan",
    "dhcp", "dns", "nat", "routing", "route", "subnet", "ip address", "mac address",
    "arp", "interface", "port", "trunk", "access port", "cisco", "mikrotik",
    "routeros", "ios", "ssh", "nmap", "scan", "topology", "backup", "config",
    "configuration", "load balancing", "failover", "network", "device", "credential",
    "snapshot", "preflight", "rollback", "plugin", "tool", "parser", "planner",
}
REJECT_PATTERNS = (
    "poem", "essay", "biology", "recipe", "cooking", "image", "picture", "song",
    "general chatbot", "javascript app", "django", "react", "stock price",
)


def decide_network_domain(user_request: str) -> DomainDecision:
    lowered = " ".join(user_request.lower().split())
    if not lowered:
        return DomainDecision(is_network_related=False, reason="Empty request.")
    if any(pattern in lowered for pattern in REJECT_PATTERNS) and not any(term in lowered for term in ALLOW_TERMS):
        return DomainDecision(is_network_related=False, reason=NETWORK_ONLY_MESSAGE)
    for term in sorted(ALLOW_TERMS, key=len, reverse=True):
        if re.search(rf"(?<![a-z0-9_]){re.escape(term)}(?![a-z0-9_])", lowered):
            return DomainDecision(is_network_related=True, reason=f"Matched network term `{term}`.", category=_category_for_term(term))
    return DomainDecision(is_network_related=False, reason=NETWORK_ONLY_MESSAGE)


def _category_for_term(term: str) -> str:
    if term in {"router", "gateway", "ssh", "credential"}:
        return "ssh_readonly"
    if term in {"scan", "nmap", "port"}:
        return "scan"
    if term in {"topology"}:
        return "topology"
    if term in {"config", "configuration", "vlan", "dhcp", "nat", "route", "routing", "firewall"}:
        return "planning"
    if term in {"plugin", "tool", "parser", "planner"}:
        return "plugin"
    return "network"


def is_plugin_worthy_request(user_request: str) -> bool:
    lowered = user_request.lower()
    return any(
        phrase in lowered
        for phrase in (
            "create a reusable tool",
            "make a reusable tool",
            "build a reusable tool",
            "make a parser",
            "create a parser",
            "build a planner plugin",
            "create a plugin",
            "generate plugin",
            "add a new tool",
        )
    )
