"""Rich result renderers for Agent tool results.

Raw JSON is never shown by default. Trace mode reveals raw details.
"""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from app.agent.agent_models import AgentResult

console = Console()

# ---------------------------------------------------------------------------
# Trace-mode session flag (module-level, lives for the process lifetime)
# ---------------------------------------------------------------------------
_trace_enabled: bool = False


def is_trace_enabled() -> bool:
    return _trace_enabled


def set_trace(enabled: bool) -> None:
    global _trace_enabled
    _trace_enabled = enabled


# ---------------------------------------------------------------------------
# Result-type inference
# ---------------------------------------------------------------------------

_RESULT_TYPE_MAP: dict[str, str] = {
    "scan_network": "scan_result",
    "workflow_scan_and_diagnose": "scan_result",
    "show_devices": "devices_list",
    "enrich_devices": "devices_list",
    "nmap_scan_local": "nmap_result",
    "nmap_scan_host": "nmap_result",
    "nmap_scan_device": "nmap_result",
    "build_topology": "topology_snapshot",
    "show_topology": "topology_snapshot",
    "rebuild_topology_with_manual": "topology_snapshot",
    "workflow_topology_report": "topology_snapshot",
    "list_snapshots": "snapshot_summary",
    "show_snapshot": "snapshot_summary",
    "capture_snapshot": "snapshot_summary",
    "create_vlan_plan": "plan_summary",
    "create_cisco_description_plan": "plan_summary",
    "create_cisco_access_port_plan": "plan_summary",
    "create_mikrotik_address_plan": "plan_summary",
    "create_mikrotik_dhcp_plan": "plan_summary",
    "custom_plan_goal": "plan_summary",
    "generate_plugin_tool": "plugin_result",
    "answer_network_fact": "network_fact",
}


def _infer_result_type(result: AgentResult) -> str:
    mapped = _RESULT_TYPE_MAP.get(result.action)
    if mapped:
        return mapped
    if isinstance(result.data, dict):
        keys = set(result.data.keys())
        if {"network", "live_hosts", "devices"}.issubset(keys):
            return "scan_result"
        if {"target", "profile", "devices"}.issubset(keys):
            return "nmap_result"
        if {"snapshot_id", "nodes", "edges"}.issubset(keys):
            return "topology_snapshot"
        if {"gateway_ip"}.issubset(keys):
            return "network_fact"
    return "generic"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def print_result(result: AgentResult) -> None:
    """Render an AgentResult with Rich formatting. No raw JSON by default."""
    _print_summary_panel(result)
    result_type = _infer_result_type(result)
    if result.data:
        _dispatch_renderer(result_type, result)
    if _trace_enabled:
        _render_trace_planner(result)
    if _trace_enabled and result.data:
        _print_raw(result.data)


# ---------------------------------------------------------------------------
# Summary panel (always shown)
# ---------------------------------------------------------------------------

def _print_summary_panel(result: AgentResult) -> None:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold green")
    table.add_column()
    table.add_row("Action:", result.action)
    table.add_row("Risk:", result.risk_level)
    table.add_row("Policy:", result.policy_decision or "allowed")
    table.add_row("Result:", result.message)
    if result.next_command:
        table.add_row("Next:", result.next_command)
    border = "green" if result.ok else "yellow"
    console.print(Panel(table, title="Network Assistant Agent", border_style=border, expand=False))


# ---------------------------------------------------------------------------
# Renderer dispatch
# ---------------------------------------------------------------------------

def _dispatch_renderer(result_type: str, result: AgentResult) -> None:
    data = result.data
    if result_type == "scan_result":
        _render_scan_result(data)
    elif result_type == "devices_list":
        _render_devices_list(data)
    elif result_type == "nmap_result":
        _render_nmap_result(data)
    elif result_type == "topology_snapshot":
        _render_topology_snapshot(data)
    elif result_type == "plan_summary":
        _render_plan_summary(data)
    elif result_type == "snapshot_summary":
        _render_snapshot_summary(data)
    elif result_type == "plugin_result":
        _render_plugin_result(data)
    elif result_type == "network_fact":
        _render_network_fact(data)
    else:
        # generic: only show next-actions and suggested commands, never raw keys
        _render_generic(result)


# ---------------------------------------------------------------------------
# scan_result
# ---------------------------------------------------------------------------

def _render_scan_result(data: dict | list) -> None:
    if not isinstance(data, dict):
        return
    network = data.get("network", "--")
    live_hosts = data.get("live_hosts", "--")
    inventory_total = data.get("inventory_total") or len(data.get("devices") or [])

    info = Table.grid(padding=(0, 2))
    info.add_column(style="bold cyan")
    info.add_column()
    info.add_row("Network:", str(network))
    info.add_row("Live hosts found:", str(live_hosts))
    info.add_row("Inventory total:", str(inventory_total))
    console.print(Panel(info, title="Scan Summary", border_style="cyan"))

    devices = data.get("devices") or []
    if devices:
        tbl = Table(title="Discovered Devices", border_style="green", show_lines=False)
        tbl.add_column("IP", style="bold")
        tbl.add_column("Vendor")
        tbl.add_column("Type")
        tbl.add_column("Open Ports")
        for dev in devices:
            ports = dev.get("ports") or []
            port_str = ", ".join(str(p) for p in ports) if ports else "--"
            tbl.add_row(
                str(dev.get("ip", "--")),
                str(dev.get("vendor") or "Unknown"),
                str(dev.get("type") or "Unknown"),
                port_str,
            )
        console.print(tbl)

    _render_suggested_next(data, default_actions=[
        "enrich devices",
        "diagnose network",
        "build topology",
        "connect to my router",
    ])
    _maybe_suggest_gateway_nmap(devices)


def _maybe_suggest_gateway_nmap(devices: list) -> None:
    for dev in devices:
        dtype = (dev.get("type") or "").lower()
        if "gateway" in dtype or "router" in dtype:
            ip = dev.get("ip")
            if ip:
                console.print(f"[dim]  nmap scan {ip}[/dim]")
            return


# ---------------------------------------------------------------------------
# devices_list
# ---------------------------------------------------------------------------

def _render_devices_list(data: dict | list) -> None:
    devices = data if isinstance(data, list) else (data.get("devices") or [])
    if not devices:
        return
    tbl = Table(title="Inventory Devices", border_style="green", show_lines=False)
    tbl.add_column("IP", style="bold")
    tbl.add_column("Vendor")
    tbl.add_column("Type")
    tbl.add_column("Open Ports")
    for dev in devices:
        if isinstance(dev, dict):
            ports = dev.get("ports") or []
            port_str = ", ".join(str(p) for p in ports) if ports else "--"
            tbl.add_row(
                str(dev.get("ip", "--")),
                str(dev.get("vendor") or "Unknown"),
                str(dev.get("type") or "Unknown"),
                port_str,
            )
    console.print(tbl)


# ---------------------------------------------------------------------------
# nmap_result
# ---------------------------------------------------------------------------

def _render_nmap_result(data: dict | list) -> None:
    if not isinstance(data, dict):
        return
    info = Table.grid(padding=(0, 2))
    info.add_column(style="bold cyan")
    info.add_column()
    info.add_row("Target:", str(data.get("target", "--")))
    info.add_row("Profile:", str(data.get("profile", "--")))
    info.add_row("Live hosts:", str(data.get("live_hosts_count", "--")))
    console.print(Panel(info, title="Nmap Scan", border_style="cyan"))

    devices = data.get("devices") or []
    if devices:
        tbl = Table(title="Nmap Results", border_style="green", show_lines=False)
        tbl.add_column("Host", style="bold")
        tbl.add_column("Port")
        tbl.add_column("Protocol")
        tbl.add_column("State")
        tbl.add_column("Service")
        tbl.add_column("Product/Version")
        for dev in devices:
            host = dev.get("ip_address") or dev.get("ip", "--")
            ports = dev.get("ports") or []
            if ports:
                for port_info in ports:
                    if isinstance(port_info, dict):
                        tbl.add_row(
                            str(host),
                            str(port_info.get("port", "--")),
                            str(port_info.get("protocol", "tcp")),
                            str(port_info.get("state", "open")),
                            str(port_info.get("service_name") or "--"),
                            str(port_info.get("product") or port_info.get("version") or "--"),
                        )
                    else:
                        tbl.add_row(str(host), str(port_info), "tcp", "open", "--", "--")
            else:
                tbl.add_row(str(host), "--", "--", "--", "--", "--")
        console.print(tbl)


# ---------------------------------------------------------------------------
# topology_snapshot
# ---------------------------------------------------------------------------

def _render_topology_snapshot(data: dict | list) -> None:
    if not isinstance(data, dict):
        return
    info = Table.grid(padding=(0, 2))
    info.add_column(style="bold cyan")
    info.add_column()
    info.add_row("Snapshot ID:", str(data.get("snapshot_id", "--")))
    info.add_row("Nodes:", str(data.get("nodes", "--")))
    info.add_row("Edges:", str(data.get("edges", "--")))
    console.print(Panel(info, title="Topology Snapshot", border_style="cyan"))


# ---------------------------------------------------------------------------
# plan_summary
# ---------------------------------------------------------------------------

def _render_plan_summary(data: dict | list) -> None:
    if not isinstance(data, dict):
        return
    plan_id = data.get("plan_id") or data.get("id")
    if not plan_id:
        return
    info = Table.grid(padding=(0, 2))
    info.add_column(style="bold cyan")
    info.add_column()
    info.add_row("Plan ID:", str(plan_id))
    for key in ("status", "risk", "title", "plan_type"):
        if key in data:
            info.add_row(f"{key.replace('_', ' ').title()}:", str(data[key]))
    next_cmds = data.get("next_commands") or []
    if next_cmds:
        info.add_row("Next steps:", "\n".join(str(c) for c in next_cmds))
    console.print(Panel(info, title="Change Plan", border_style="cyan"))


# ---------------------------------------------------------------------------
# snapshot_summary
# ---------------------------------------------------------------------------

def _render_snapshot_summary(data: dict | list) -> None:
    if isinstance(data, list):
        if not data:
            return
        tbl = Table(title="Config Snapshots", border_style="green")
        tbl.add_column("ID", style="bold")
        tbl.add_column("Device")
        tbl.add_column("Type")
        tbl.add_column("Plan ID")
        for snap in data:
            if isinstance(snap, dict):
                tbl.add_row(
                    str(snap.get("id", "--")),
                    str(snap.get("device") or "--"),
                    str(snap.get("type") or snap.get("snapshot_type") or "--"),
                    str(snap.get("plan_id") or "--"),
                )
        console.print(tbl)
    elif isinstance(data, dict):
        info = Table.grid(padding=(0, 2))
        info.add_column(style="bold cyan")
        info.add_column()
        for key in ("id", "type", "snapshot_type", "platform", "device", "plan_id", "created_at"):
            if key in data and data[key] is not None:
                info.add_row(f"{key.replace('_', ' ').title()}:", str(data[key]))
        console.print(Panel(info, title="Config Snapshot", border_style="cyan"))


# ---------------------------------------------------------------------------
# plugin_result
# ---------------------------------------------------------------------------

def _render_plugin_result(data: dict | list) -> None:
    if not isinstance(data, dict):
        return
    info = Table.grid(padding=(0, 2))
    info.add_column(style="bold cyan")
    info.add_column()
    for key in ("tool_name", "status", "validation_status", "category", "risk", "summary"):
        if key in data and data[key] is not None:
            info.add_row(f"{key.replace('_', ' ').title()}:", str(data[key]))
    run_result = data.get("run_result")
    if isinstance(run_result, dict):
        info.add_row("Run result:", str(run_result.get("summary", "--")))
    console.print(Panel(info, title="Plugin Result", border_style="cyan"))


# ---------------------------------------------------------------------------
# network_fact
# ---------------------------------------------------------------------------

def _render_network_fact(data: dict | list) -> None:
    if not isinstance(data, dict):
        return
    info = Table.grid(padding=(0, 2))
    info.add_column(style="bold cyan")
    info.add_column()
    for key, label in [
        ("gateway_ip", "Gateway IP"),
        ("vendor", "Vendor"),
        ("device_type", "Type"),
        ("open_ports", "Open Ports"),
        ("local_ip", "Local IP"),
        ("interface", "Interface"),
        ("network", "Network"),
        ("cidr", "CIDR"),
    ]:
        val = data.get(key)
        if val is not None:
            if isinstance(val, list):
                val = ", ".join(str(p) for p in val) if val else "--"
            info.add_row(f"{label}:", str(val))
    console.print(Panel(info, title="Gateway Information", border_style="cyan"))

    evidence = data.get("evidence") or []
    if evidence:
        ev_lines = "\n".join(f"- {e}" for e in evidence)
        console.print(Panel(ev_lines, title="Evidence", border_style="dim"))

    note = data.get("note")
    if note:
        console.print(Panel(note, title="Note", border_style="yellow"))


# ---------------------------------------------------------------------------
# generic fallback
# ---------------------------------------------------------------------------

def _render_generic(result: AgentResult) -> None:
    if not isinstance(result.data, dict):
        return
    actions = result.data.get("next_actions") or result.data.get("suggested_commands") or []
    if actions:
        console.print("[bold]Suggested next:[/bold]")
        for action in actions:
            console.print(f"  - {action}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _render_suggested_next(data: dict, default_actions: list[str]) -> None:
    actions = data.get("task_chain") or default_actions
    console.print("[bold]Suggested next:[/bold]")
    for action in actions:
        console.print(f"  - {action}")


def _print_raw(data: dict | list) -> None:
    import json
    from rich.json import JSON
    compact = json.dumps(data, indent=2, default=str)
    if len(compact) > 4000:
        compact = compact[:4000] + "\n... truncated ..."
    console.print(Panel(JSON(compact), title="[dim]Raw tool details (trace mode)[/dim]", border_style="dim"))


def _render_trace_planner(result: AgentResult) -> None:
    if not isinstance(result.data, dict):
        return
    planner = result.data.get("_planner")
    if not isinstance(planner, dict):
        return

    info = Table.grid(padding=(0, 2))
    info.add_column(style="bold magenta")
    info.add_column()
    info.add_row("Selected skill:", str(planner.get("selected_skill", "--")))
    info.add_row("Selected tool:", str(planner.get("selected_tool", "--")))
    info.add_row("Reason:", str(planner.get("planner_reason", "--")))
    info.add_row("Confidence:", str(planner.get("planner_confidence", "--")))
    if result.policy_decision:
        info.add_row("Policy decision:", result.policy_decision)

    candidates = planner.get("candidate_skills") or []
    if candidates:
        info.add_row("Candidate skills:", ", ".join(str(item) for item in candidates))
    tools = planner.get("candidate_tools") or []
    if tools:
        info.add_row("Candidate tools:", ", ".join(str(item) for item in tools))

    console.print(Panel(info, title="Planner Trace", border_style="magenta"))
