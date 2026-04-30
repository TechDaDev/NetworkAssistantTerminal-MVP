from __future__ import annotations

import re


class CommandPolicyError(ValueError):
    """Raised when a command is not approved for read-only execution."""


CISCO_IOS_ALLOWED = {
    "show version",
    "show running-config",
    "show startup-config",
    "show ip interface brief",
    "show interfaces status",
    "show vlan brief",
    "show interfaces trunk",
    "show mac address-table",
    "show cdp neighbors detail",
    "show lldp neighbors detail",
    "show ip route",
    "show access-lists",
    "show logging",
}

MIKROTIK_ROUTEROS_ALLOWED = {
    "/export terse",
    "/system resource print",
    "/system identity print",
    "/interface print",
    "/ip address print",
    "/ip route print",
    "/ipv6 route print",
    "/ip service print",
    "/ip firewall filter print",
    "/ip firewall nat print",
    "/ip firewall mangle print",
    "/ip dhcp-server lease print",
    "/ip pool print",
    "/ip dhcp-server print",
    "/ip dhcp-server network print",
    "/ip arp print",
    "/routing table print",
    "/routing rule print",
}

LINUX_ALLOWED = {
    "uname -a",
    "ip addr show",
    "ip route show",
    "hostname",
    "df -h",
    "free -m",
    "uptime",
}

PLATFORM_ALLOWLISTS = {
    "cisco_ios": CISCO_IOS_ALLOWED,
    "mikrotik_routeros": MIKROTIK_ROUTEROS_ALLOWED,
    "linux": LINUX_ALLOWED,
}

COLLECTION_COMMANDS = {
    "cisco_ios": [
        "show version",
        "show ip interface brief",
        "show vlan brief",
        "show interfaces status",
        "show cdp neighbors detail",
        "show lldp neighbors detail",
    ],
    "mikrotik_routeros": [
        "/system resource print",
        "/system identity print",
        "/interface print",
        "/ip address print",
        "/ip route print",
        "/ip service print",
        "/ip pool print",
        "/ip dhcp-server print",
        "/ip dhcp-server network print",
    ],
    "linux": [
        "hostname",
        "uname -a",
        "ip addr show",
        "ip route show",
        "uptime",
    ],
}

DANGEROUS_PATTERNS = (
    "configure",
    "conf t",
    "write",
    "erase",
    "delete",
    "reload",
    "reboot",
    "shutdown",
    "set ",
    "add ",
    "remove",
    "enable secret",
    "password",
    "copy",
    "format",
    "reset",
    "factory-reset",
)

MIKROTIK_DANGEROUS_PATTERNS = (
    "/system reset-configuration",
    "/export file",
    "disable",
    "enable",
)

SENSITIVE_READONLY_COMMANDS = {
    "show running-config",
    "show startup-config",
}


def normalize_command(command: str) -> str:
    return " ".join(command.strip().split())


def reject_dangerous_patterns(command: str, platform: str | None = None) -> None:
    normalized = normalize_command(command)
    lowered = normalized.lower()
    for pattern in DANGEROUS_PATTERNS:
        if pattern in lowered:
            raise CommandPolicyError(f"Blocked command: contains dangerous pattern `{pattern}`.")

    if platform == "mikrotik_routeros" or lowered.startswith("/"):
        for pattern in MIKROTIK_DANGEROUS_PATTERNS:
            if pattern in lowered:
                raise CommandPolicyError(f"Blocked MikroTik command: contains `{pattern}`.")


def validate_readonly_command(platform: str, command: str) -> None:
    normalized = normalize_command(command)
    reject_dangerous_patterns(normalized, platform=platform)

    allowed = PLATFORM_ALLOWLISTS.get(platform)
    if allowed is None:
        raise CommandPolicyError(f"No read-only command allowlist exists for platform `{platform}`.")
    if platform == "cisco_ios" and re.fullmatch(
        r"show running-config interface (?:Gi|GigabitEthernet|Fa|FastEthernet|Te|TenGigabitEthernet|Eth|Ethernet)\d+(?:/\d+){1,3}",
        normalized,
        flags=re.IGNORECASE,
    ):
        return
    if normalized not in allowed:
        raise CommandPolicyError(f"Command is not allowlisted for `{platform}`: {normalized}")


def collection_commands_for(platform: str) -> list[str]:
    commands = COLLECTION_COMMANDS.get(platform)
    if not commands:
        raise CommandPolicyError(f"No safe collection command set exists for platform `{platform}`.")
    return list(commands)


def is_sensitive_readonly_command(command: str) -> bool:
    return normalize_command(command) in SENSITIVE_READONLY_COMMANDS
