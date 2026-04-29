from __future__ import annotations

import ipaddress

from app.agent.agent_models import PolicyDecision
from app.agent.tool_registry import get_tool_spec


UNSAFE_AGENT_PATTERNS = (
    "ssh ",
    "telnet ",
    "netmiko",
    "send_command",
    "send_config",
    "shell",
    "bash",
    "sudo",
    "configure terminal",
    "conf t",
    "/system reset",
    "/tool",
    "/user",
    "password",
    "brute force",
    "bypass password",
    "dump credentials",
    "exploit",
    "reset",
    "reboot",
    "erase",
    "delete config",
    "disable firewall",
    "open all ports",
)


def evaluate_agent_action(tool_name: str, args: dict) -> PolicyDecision:
    spec = get_tool_spec(tool_name)
    if spec is None:
        return PolicyDecision(False, "high", message="Unknown tools are blocked in agent mode.")

    if tool_name == "blocked_request":
        return PolicyDecision(
            False,
            "high",
            message=args.get("reason", "Request blocked by agent safety policy."),
        )

    unsafe = _unsafe_arg(args)
    if unsafe:
        return PolicyDecision(False, "high", message=f"Unsafe input blocked: {unsafe}")

    if spec.direct_cli_required or not spec.allowed_in_agent:
        command = _direct_cli_command(spec.direct_cli_template, args)
        return PolicyDecision(
            False,
            spec.risk_level,
            direct_cli_required=True,
            message="This action requires direct CLI confirmation and cannot be executed from agent mode.",
            direct_cli_command=command,
        )

    return PolicyDecision(
        True,
        spec.risk_level,
        requires_confirmation=spec.requires_confirmation,
        message=spec.reason or f"Action `{tool_name}` is allowed by agent policy.",
    )


def _unsafe_arg(args: dict) -> str | None:
    for key, value in args.items():
        text = str(value).lower()
        for pattern in UNSAFE_AGENT_PATTERNS:
            if pattern in text:
                return f"{key} contains `{pattern.strip()}`"
    target = args.get("target_ip") or args.get("ip")
    if target:
        try:
            ip = ipaddress.ip_address(str(target))
        except ValueError:
            return None
        if not ip.is_private:
            return "public IP targets are blocked from agent mode"
    return None


def _direct_cli_command(template: str | None, args: dict) -> str | None:
    if not template:
        return None
    try:
        return template.format(**args)
    except KeyError:
        return template
