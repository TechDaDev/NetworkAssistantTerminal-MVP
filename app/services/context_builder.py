from __future__ import annotations

import json
import re

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.database import get_session, init_db
from app.models import CommandRun, Device, DeviceKnowledge, ScanRun
from app.services.knowledge import KnowledgeSearchResult, search_related_knowledge
from app.services.topology import latest_topology_context_summary


SECRET_LINE_PATTERNS = (
    re.compile(r".*(password|passwd|secret|token|api[_-]?key|private key).*", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.IGNORECASE),
)


def build_local_network_context(question: str) -> str:
    init_db()
    with get_session() as session:
        latest_scan = session.scalar(select(ScanRun).order_by(ScanRun.finished_at.desc()))
        devices = list(
            session.scalars(
                select(Device)
                .options(
                    selectinload(Device.ports),
                    selectinload(Device.observations),
                    selectinload(Device.command_runs),
                )
                .order_by(Device.ip_address)
            ).all()
        )
        knowledge = search_related_knowledge(question, limit=3)

    sections = [
        "# Local Network Context",
        _latest_scan_section(latest_scan),
        _inventory_boundary_section(devices),
        _devices_section(devices),
        latest_topology_context_summary(),
        _command_runs_section(devices),
        _knowledge_section(knowledge),
        _safe_manual_commands_section(),
        "# Safety Boundary\nThis context is read-only local data. The assistant must not run scans, connect to devices, run commands, ask for credentials, or modify configurations.",
    ]
    return redact_sensitive_text("\n\n".join(section for section in sections if section.strip()))


def redact_sensitive_text(text: str) -> str:
    redacted_lines: list[str] = []
    for line in text.splitlines():
        if any(pattern.match(line) for pattern in SECRET_LINE_PATTERNS):
            redacted_lines.append("[REDACTED SECRET LINE]")
        else:
            redacted_lines.append(_redact_inline_secrets(line))
    return "\n".join(redacted_lines)


def _redact_inline_secrets(line: str) -> str:
    patterns = (
        r"(?i)(password\s*[:=]\s*)\S+",
        r"(?i)(token\s*[:=]\s*)\S+",
        r"(?i)(api[_-]?key\s*[:=]\s*)\S+",
        r"(?i)(secret\s*[:=]\s*)\S+",
    )
    redacted = line
    for pattern in patterns:
        redacted = re.sub(pattern, r"\1[REDACTED]", redacted)
    return redacted


def _latest_scan_section(scan: ScanRun | None) -> str:
    if scan is None:
        return "# Latest Scan\nNo scan has been stored yet."
    summary = {}
    try:
        summary = json.loads(scan.summary_json or "{}")
    except json.JSONDecodeError:
        summary = {}
    network = summary.get("network_info", {})
    return (
        "# Latest Scan\n"
        f"Finished: {scan.finished_at}\n"
        f"Interface: {scan.interface_name}\n"
        f"Local IP: {scan.local_ip}\n"
        f"CIDR: {scan.cidr}\n"
        f"Gateway: {scan.gateway_ip or '--'}\n"
        "Gateway note: this is the configured default gateway from network detection; "
        "it is not proof that the gateway was discovered as a live host.\n"
        f"Live hosts: {scan.live_hosts_count}\n"
        f"Safe to scan at time of detection: {network.get('safe_to_scan', '--')}"
    )


def _devices_section(devices: list[Device]) -> str:
    if not devices:
        return "# Devices\nNo devices are stored."
    lines = ["# Devices"]
    for device in devices[:50]:
        ports = ", ".join(
            f"{port.port}/{port.protocol} {port.service_guess}"
            for port in sorted(device.ports, key=lambda item: item.port)
            if port.state == "open"
        ) or "--"
        observations = "; ".join(
            f"{observation.observation_type}={observation.observation_value} ({observation.confidence}, {observation.source})"
            for observation in sorted(device.observations, key=lambda item: item.created_at, reverse=True)[:8]
        ) or "--"
        lines.append(
            f"- {device.ip_address}: hostname={device.hostname or '--'}, "
            f"mac={device.mac_address or '--'}, vendor={device.vendor_guess}, "
            f"type={device.device_type_guess}, confidence={device.confidence}, "
            f"open_ports={ports}, observations={observations}"
        )
    return "\n".join(lines)


def _inventory_boundary_section(devices: list[Device]) -> str:
    stored_ips = ", ".join(device.ip_address for device in devices) or "none"
    return (
        "# Stored Device Inventory Boundary\n"
        f"Stored device IPs: {stored_ips}\n"
        "Do not recommend `python main.py device <ip>`, `python main.py connect ...`, "
        "or `python main.py command history <ip>` for IPs that are not in this stored device IP list."
    )


def _command_runs_section(devices: list[Device]) -> str:
    runs: list[tuple[str, CommandRun]] = []
    for device in devices:
        runs.extend((device.ip_address, run) for run in device.command_runs)
    runs.sort(key=lambda item: item[1].started_at, reverse=True)
    if not runs:
        return "# Recent Command Runs\nNo command history is stored."

    lines = ["# Recent Command Runs"]
    for ip_address, run in runs[:20]:
        preview_source = run.output if run.success else run.error_message or ""
        preview = preview_source[:800].replace("\x00", "")
        lines.append(
            f"- {ip_address} | {run.started_at} | "
            f"command={run.command!r} | success={run.success} | preview={preview!r}"
        )
    return "\n".join(lines)


def _knowledge_section(items: list[KnowledgeSearchResult]) -> str:
    if not items:
        return "# Related Local Knowledge\nNo related local knowledge found."
    lines = [
        "# Related Local Knowledge",
        "These are user-added local knowledge notes, not live device evidence.",
    ]
    for result in items[:3]:
        item = result.item
        content = item.content[:1200]
        lines.append(
            f"- {item.title}: vendor={item.vendor or '--'}, model={item.model or '--'}, "
            f"doc_type={item.doc_type}, tags={item.tags or '--'}, trusted={item.is_trusted}, "
            f"source={item.source_name or item.source_url or item.source_type}, content={content}"
        )
    return "\n".join(lines)


def _safe_manual_commands_section() -> str:
    return (
        "# Safe Manual CLI Commands Available\n"
        "- python main.py report\n"
        "- python main.py devices\n"
        "- python main.py device <ip> (only for IPs listed in the stored device inventory)\n"
        "- python main.py scan\n"
        "- python main.py enrich\n"
        "- python main.py connect test <ip> (only for stored devices with stored credentials)\n"
        "- python main.py connect collect <ip> (only for stored devices with stored credentials)\n"
        "- python main.py command history <ip> (only for IPs listed in the stored device inventory)\n"
        "The assistant may recommend these commands for the user to run manually, but must not run them."
    )
