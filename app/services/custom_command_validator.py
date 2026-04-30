from __future__ import annotations

import ipaddress
import re

from pydantic import BaseModel


class CustomCommandClassification(BaseModel):
    command: str
    platform: str
    category: str
    reasons: list[str]


BLOCKED_PATTERNS = (
    "brute force",
    "bypass",
    "exploit",
    "private key",
    "/tool fetch",
    " curl ",
    "wget",
    "scp",
    "ftp",
    "tftp",
    "/user export",
    "enable secret",
    "crypto key",
    "/user add",
    "/user set",
    "/system reset-configuration",
)
SHELL_OPERATORS = ("&&", "||", "`", "$(", ">", "<", "\n", "\r", ";")
DOUBLE_CONFIRM_PATTERNS = (
    "default route",
    "gateway=0.0.0.0",
    "dst-address=0.0.0.0/0",
    "no ip route 0.0.0.0",
    "remove",
    "disable",
    "no ip access-group",
    "ip access-group",
    "switchport mode trunk",
    "switchport mode access",
    "dhcp",
    "firewall",
    "nat",
    "mangle",
    "route",
    "routing",
)


ROUTEROS_READONLY_PREFIXES = (
    "/interface print",
    "/ip address print",
    "/ip route print",
    "/ip firewall nat print",
    "/ip firewall mangle print",
    "/ip firewall filter print",
    "/ip pool print",
    "/ip dhcp-server print",
    "/routing table print",
    "/routing rule print",
    "/export terse",
)
CISCO_READONLY_PREFIXES = (
    "show running-config",
    "show ip interface brief",
    "show ip route",
    "show access-lists",
    "show interfaces status",
    "show vlan brief",
)


def classify_custom_command(command: str, platform: str, plan_comment: str | None = None) -> CustomCommandClassification:
    normalized = _normalize(command)
    lowered = normalized.lower()
    reasons: list[str] = []

    if not normalized:
        return CustomCommandClassification(command=command, platform=platform, category="blocked_security_abuse", reasons=["Empty command."])
    if _has_shell_operator(command):
        return CustomCommandClassification(command=command, platform=platform, category="blocked_security_abuse", reasons=["Shell-style operators or command chaining are blocked."])
    if _targets_public_ip(lowered):
        return CustomCommandClassification(command=command, platform=platform, category="blocked_security_abuse", reasons=["Public/unauthorized targets are blocked in generated config commands."])
    for pattern in BLOCKED_PATTERNS:
        if pattern in f" {lowered} " or pattern in lowered:
            return CustomCommandClassification(command=command, platform=platform, category="blocked_security_abuse", reasons=[f"Blocked security-abuse pattern `{pattern}`."])
    if platform == "cisco_ios" and re.search(r"\busername\s+\S+\s+(?:password|secret)\b", lowered):
        return CustomCommandClassification(command=command, platform=platform, category="blocked_security_abuse", reasons=["Cisco user/secret changes are blocked."])

    tagged_remove = bool(plan_comment and plan_comment.lower() in lowered and (" remove " in f" {lowered} " or lowered.startswith("no ")))
    for pattern in DOUBLE_CONFIRM_PATTERNS:
        if pattern in lowered and not tagged_remove:
            reasons.append(f"May disrupt network behavior: `{pattern}`.")
    if reasons:
        return CustomCommandClassification(command=command, platform=platform, category="requires_double_confirmation", reasons=reasons)
    return CustomCommandClassification(command=command, platform=platform, category="allowed_after_confirmation", reasons=["Allowed after explicit high-impact confirmation."])


def validate_precheck_command(command: str, platform: str) -> None:
    normalized = _normalize(command)
    lowered = normalized.lower()
    if _has_shell_operator(command):
        raise ValueError("Precheck command contains blocked shell/operator syntax.")
    if platform == "cisco_ios" and any(lowered.startswith(prefix) for prefix in CISCO_READONLY_PREFIXES):
        return
    if platform == "mikrotik_routeros" and any(lowered.startswith(prefix) for prefix in ROUTEROS_READONLY_PREFIXES):
        return
    raise ValueError(f"Precheck command is not read-only for `{platform}`: {command}")


def validate_verification_command(command: str, platform: str) -> None:
    normalized = _normalize(command)
    lowered = normalized.lower()
    if _has_shell_operator(command):
        raise ValueError("Verification command contains blocked shell/operator syntax.")
    if platform == "cisco_ios" and lowered.startswith("show "):
        return
    if platform == "mikrotik_routeros":
        if any(lowered.startswith(prefix) for prefix in ROUTEROS_READONLY_PREFIXES):
            return
        if lowered.startswith("/ping ") and _routeros_ping_is_limited(lowered):
            return
    raise ValueError(f"Verification command is not read-only for `{platform}`: {command}")


def classify_commands(commands: list[str], platform: str, plan_comment: str | None = None) -> list[CustomCommandClassification]:
    return [classify_custom_command(command, platform, plan_comment=plan_comment) for command in commands]


def has_double_confirmation(classifications: list[CustomCommandClassification]) -> bool:
    return any(item.category == "requires_double_confirmation" for item in classifications)


def has_blocked_command(classifications: list[CustomCommandClassification]) -> bool:
    return any(item.category == "blocked_security_abuse" for item in classifications)


def _normalize(command: str) -> str:
    return " ".join(command.strip().split())


def _has_shell_operator(command: str) -> bool:
    return any(operator in command for operator in SHELL_OPERATORS)


def _targets_public_ip(lowered: str) -> bool:
    for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", lowered):
        try:
            ip = ipaddress.ip_address(match)
        except ValueError:
            continue
        if not ip.is_private:
            return True
    return False


def _routeros_ping_is_limited(lowered: str) -> bool:
    if " count=" not in lowered:
        return False
    target = lowered.split(maxsplit=1)[1].split()[0]
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        return False
    return ip.is_private or str(ip) == "8.8.8.8"
