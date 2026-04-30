from __future__ import annotations

import ipaddress
import shlex
from dataclasses import dataclass

from app.services.config_planner import archive_change_plan, create_cisco_access_port_plan, create_cisco_description_plan, create_mikrotik_address_plan, create_mikrotik_dhcp_plan, create_vlan_plan, get_change_plan, list_change_plans, reject_change_plan, review_change_plan
from app.services.config_planner import run_preflight
from app.services.config_snapshot import generate_restore_guidance, list_snapshots, show_snapshot
from app.safety import validate_scan_target
from app.services.diagnostics import (
    diagnose_connectivity,
    diagnose_device,
    diagnose_management_ports,
    diagnose_network,
)
from app.services.enrichment import enrich_stored_devices
from app.services.inventory import get_device_profile, get_latest_scan_report, list_devices, save_scan_result
from app.services.knowledge import get_knowledge, list_knowledge, search_knowledge
from app.services.llm_planner import LLMPlanner
from app.services.manual_topology import list_manual_edges, list_manual_nodes, list_manual_notes
from app.services.network_detection import detect_local_network
from app.services.nmap_tool import (
    get_nmap_version,
    is_nmap_available,
    run_nmap_scan,
    save_nmap_results,
    validate_nmap_profile,
    validate_nmap_target,
)
from app.services.scanner import scan_network
from app.services.topology import build_topology_snapshot, explain_topology, export_topology_mermaid, get_latest_topology, rebuild_topology_with_manual
from app.services.topology_awareness import analyze_plan_topology_risk
from app.services.serializers import (
    change_plan_to_dict,
    device_to_dict,
    diagnostic_to_dict,
    knowledge_search_result_to_dict,
    knowledge_to_dict,
    manual_topology_edge_to_dict,
    manual_topology_node_to_dict,
    manual_topology_note_to_dict,
    scan_result_to_dict,
    scan_run_to_dict,
    config_snapshot_to_dict,
)


@dataclass
class RoutedCommandResult:
    ok: bool
    kind: str
    message: str
    data: dict | list | None = None

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "kind": self.kind,
            "message": self.message,
            "data": self.data,
        }


def route_local_command(text: str) -> RoutedCommandResult:
    command = " ".join(text.strip().split())
    lowered = command.lower()
    if not command:
        return RoutedCommandResult(False, "empty", "No command provided.")

    if lowered in {"help", "?"}:
        return _help()
    if lowered in {"show devices", "devices", "list devices"}:
        devices = [device_to_dict(device) for device in list_devices()]
        return RoutedCommandResult(True, "devices", f"{len(devices)} device(s) in inventory.", devices)
    if lowered in {"report latest", "latest report", "show report", "report"}:
        return _latest_report()
    if lowered == "build topology":
        result = build_topology_snapshot()
        return RoutedCommandResult(True, "topology", f"Built topology snapshot #{result.snapshot.id}.", {"snapshot_id": result.snapshot.id, "warnings": result.warnings})
    if lowered == "show topology":
        result = get_latest_topology()
        if result is None:
            return RoutedCommandResult(False, "topology", "No topology snapshot exists. Run `build topology` first.")
        return RoutedCommandResult(True, "topology", f"Topology snapshot #{result.snapshot.id}: {len(result.nodes)} node(s), {len(result.edges)} edge(s).")
    if lowered == "export topology mermaid":
        return RoutedCommandResult(True, "topology", export_topology_mermaid())
    if lowered.startswith("export topology ") and " to " in lowered:
        return RoutedCommandResult(
            False,
            "topology",
            "Topology file export should use direct CLI, for example: "
            "`python main.py topology export-file --format mermaid --output topology.md`.",
        )
    if lowered.startswith("topology report to "):
        return RoutedCommandResult(
            False,
            "topology",
            "Topology report file writing should use direct CLI: "
            "`python main.py topology report --output network_topology_report.md`.",
        )
    if lowered == "explain topology":
        result = explain_topology()
        return RoutedCommandResult(True, "topology", result.summary, diagnostic_to_dict(result))
    if lowered.startswith(("topology risk check plan ", "risk check plan ")):
        parts = command.split()
        value = parts[-1] if parts else ""
        if not value.isdigit():
            return RoutedCommandResult(False, "topology", "Plan ID must be a number.")
        plan = get_change_plan(int(value))
        if plan is None:
            return RoutedCommandResult(False, "topology", f"Change plan {value} not found.")
        findings = analyze_plan_topology_risk(plan)
        return RoutedCommandResult(
            True,
            "topology",
            f"Topology risk check found {len(findings)} finding(s).",
            {"plan_id": int(value), "findings": [finding.model_dump(mode="json") for finding in findings]},
        )
    if lowered in {"list snapshots", "snapshot list", "snapshots"}:
        snapshots = [config_snapshot_to_dict(snapshot) for snapshot in list_snapshots()]
        return RoutedCommandResult(True, "snapshot", f"{len(snapshots)} config snapshot(s).", snapshots)
    if lowered.startswith("show snapshot "):
        value = command.rsplit(" ", 1)[-1]
        if not value.isdigit():
            return RoutedCommandResult(False, "snapshot", "Snapshot ID must be a number.")
        snapshot = show_snapshot(int(value))
        if snapshot is None:
            return RoutedCommandResult(False, "snapshot", f"Snapshot {value} not found.")
        data = config_snapshot_to_dict(snapshot)
        data["content_preview"] = (snapshot.content or "")[:2000]
        return RoutedCommandResult(True, "snapshot", f"Snapshot {value}.", data)
    if lowered.startswith(("snapshot restore guidance ", "restore guidance snapshot ")):
        value = command.rsplit(" ", 1)[-1]
        if not value.isdigit():
            return RoutedCommandResult(False, "snapshot", "Snapshot ID must be a number.")
        guidance = generate_restore_guidance(int(value))
        return RoutedCommandResult(
            True,
            "snapshot",
            guidance.summary,
            {
                "snapshot_id": guidance.snapshot_id,
                "platform": guidance.platform,
                "warnings": guidance.warnings,
                "recommended_steps": guidance.recommended_steps,
                "rollback_commands": guidance.rollback_commands,
            },
        )
    if lowered.startswith("export snapshot "):
        return RoutedCommandResult(
            False,
            "snapshot",
            "Snapshot file export should use direct CLI, for example: "
            "`python main.py snapshot export <id> --format md --output snapshot.md`.",
        )
    if lowered.startswith("capture snapshot"):
        return RoutedCommandResult(
            False,
            "snapshot",
            "Manual snapshot capture should use direct CLI or agent confirmation: `python main.py snapshot capture --plan-id <id> --type manual`.",
        )
    if lowered in {"list manual topology", "show manual topology"}:
        nodes = [manual_topology_node_to_dict(node) for node in list_manual_nodes()]
        edges = [manual_topology_edge_to_dict(edge) for edge in list_manual_edges()]
        notes = [manual_topology_note_to_dict(note) for note in list_manual_notes()]
        return RoutedCommandResult(
            True,
            "topology",
            f"Manual topology: {len(nodes)} node(s), {len(edges)} edge(s), {len(notes)} note(s).",
            {"nodes": nodes, "edges": edges, "notes": notes},
        )
    if lowered == "rebuild topology with manual":
        result = rebuild_topology_with_manual()
        return RoutedCommandResult(True, "topology", f"Built topology snapshot #{result.snapshot.id} with manual corrections.", {"snapshot_id": result.snapshot.id, "warnings": result.warnings})
    if lowered.startswith("add manual topology"):
        return RoutedCommandResult(
            False,
            "topology",
            "Manual topology additions should use direct CLI structured options, for example: "
            "`python main.py topology manual-node add --key core-switch --label \"Core Switch\" --type switch`.",
        )
    if lowered.startswith(("delete manual topology", "remove manual topology")):
        return RoutedCommandResult(
            False,
            "topology",
            "Manual topology deletion requires direct CLI confirmation. Use `python main.py topology manual-node delete <id>` or the matching manual-edge/manual-note command.",
        )
    if lowered in {"scan network", "scan"}:
        return _scan_network()
    if lowered == "nmap check":
        return _nmap_check()
    if lowered.startswith("nmap scan "):
        return _route_nmap_scan(command)
    if lowered in {"enrich devices", "enrich"}:
        devices = [device_to_dict(device) for device in enrich_stored_devices()]
        return RoutedCommandResult(True, "enrich", f"Enriched {len(devices)} device(s).", devices)
    if lowered == "diagnose network":
        result = diagnose_network()
        return RoutedCommandResult(True, "diagnostic", result.summary, diagnostic_to_dict(result))
    if lowered in {"diagnose management-ports", "diagnose management ports"}:
        result = diagnose_management_ports()
        return RoutedCommandResult(True, "diagnostic", result.summary, diagnostic_to_dict(result))
    if lowered == "diagnose gateway":
        gateway = detect_local_network().gateway_ip
        if not gateway:
            return RoutedCommandResult(False, "diagnostic", "No gateway detected.")
        result = diagnose_connectivity(gateway)
        return RoutedCommandResult(True, "diagnostic", result.summary, diagnostic_to_dict(result))
    if lowered.startswith("diagnose connectivity "):
        target = command.split(maxsplit=2)[2]
        result = diagnose_connectivity(target)
        return RoutedCommandResult(True, "diagnostic", result.summary, diagnostic_to_dict(result))
    if lowered.startswith("diagnose "):
        target = command.split(maxsplit=1)[1]
        if _looks_like_ip(target):
            result = diagnose_device(target)
            return RoutedCommandResult(True, "diagnostic", result.summary, diagnostic_to_dict(result))
    if lowered.startswith("show device "):
        return _show_device(command.split(maxsplit=2)[2])
    if lowered.startswith("device "):
        return _show_device(command.split(maxsplit=1)[1])
    if lowered == "knowledge list":
        items = [knowledge_to_dict(item) for item in list_knowledge()]
        return RoutedCommandResult(True, "knowledge", f"{len(items)} knowledge document(s).", items)
    if lowered.startswith("knowledge search "):
        query = command.split(maxsplit=2)[2]
        results = [knowledge_search_result_to_dict(result) for result in search_knowledge(query)]
        return RoutedCommandResult(True, "knowledge", f"{len(results)} local knowledge result(s).", results)
    if lowered.startswith("fetch docs "):
        return _route_fetch_docs_instruction(command)
    if lowered.startswith("show knowledge "):
        value = command.split(maxsplit=2)[2]
        if not value.isdigit():
            return RoutedCommandResult(False, "knowledge", "Knowledge ID must be a number.")
        item = get_knowledge(int(value))
        if item is None:
            return RoutedCommandResult(False, "knowledge", f"Knowledge document {value} not found.")
        return RoutedCommandResult(True, "knowledge", f"Knowledge document {value}.", knowledge_to_dict(item))
    if lowered.startswith("ask "):
        question = command.split(maxsplit=1)[1]
        answer = LLMPlanner().answer_question(question)
        return RoutedCommandResult(True, "ask", "DeepSeek answered using local context.", {"answer": answer})
    if lowered.startswith("summarize "):
        answer = LLMPlanner().answer_question(command)
        return RoutedCommandResult(True, "ask", "DeepSeek answered using local context.", {"answer": answer})
    if lowered in {"plans", "plan list", "show plans"}:
        plans = [change_plan_to_dict(plan) for plan in list_change_plans()]
        return RoutedCommandResult(True, "plans", f"{len(plans)} saved change plan(s).", plans)
    if lowered.startswith("show plan "):
        value = command.split(maxsplit=2)[2]
        if not value.isdigit():
            return RoutedCommandResult(False, "plan", "Plan ID must be a number.")
        plan = get_change_plan(int(value))
        if plan is None:
            return RoutedCommandResult(False, "plan", f"Change plan {value} not found.")
        return RoutedCommandResult(True, "plan", f"Change plan {value}. PLAN ONLY -- NO COMMANDS EXECUTED.", change_plan_to_dict(plan))
    if lowered.startswith("review plan "):
        parts = command.split()
        value = parts[2] if len(parts) >= 3 else ""
        if not value.isdigit():
            return RoutedCommandResult(False, "plan", "Plan ID must be a number.")
        plan = review_change_plan(int(value), note="Reviewed from chat router")
        return RoutedCommandResult(True, "plan", f"Reviewed plan {value}. REVIEW ONLY -- NO COMMANDS EXECUTED.", change_plan_to_dict(plan))
    if lowered.startswith("approve plan "):
        parts = command.split()
        value = parts[2] if len(parts) >= 3 else ""
        if not value.isdigit():
            return RoutedCommandResult(False, "plan", "Plan ID must be a number.")
        return RoutedCommandResult(
            False,
            "plan",
            f"Approval requires explicit CLI confirmation. Run `python main.py plan approve {value}`.",
        )
    if lowered.startswith("reject plan "):
        return _route_reject_plan(command)
    if lowered.startswith("archive plan "):
        parts = command.split()
        value = parts[2] if len(parts) >= 3 else ""
        if not value.isdigit():
            return RoutedCommandResult(False, "plan", "Plan ID must be a number.")
        plan = archive_change_plan(int(value), note="Archived from chat router")
        return RoutedCommandResult(True, "plan", f"Archived plan {value}. NO COMMANDS EXECUTED.", change_plan_to_dict(plan))
    if lowered.startswith("preflight plan "):
        return _route_preflight_plan(command)
    if lowered.startswith("execute plan "):
        parts = command.split()
        value = parts[2] if len(parts) >= 3 else ""
        if not value.isdigit():
            return RoutedCommandResult(False, "execution", "Plan ID must be a number.")
        return RoutedCommandResult(
            False,
            "execution",
            "Execution is only available through direct CLI confirmation: "
            f"`python main.py plan execute {value}`.",
        )
    if lowered.startswith("save plan "):
        parts = command.split()
        value = parts[2] if len(parts) >= 3 else ""
        if not value.isdigit():
            return RoutedCommandResult(False, "execution", "Plan ID must be a number.")
        plan = get_change_plan(int(value))
        if plan and plan.plan_type in {"mikrotik_address", "mikrotik_dhcp_server"}:
            return RoutedCommandResult(
                False,
                "execution",
                "MikroTik changes are applied immediately and do not use a separate save step.",
            )
        return RoutedCommandResult(
            False,
            "execution",
            "This action requires direct CLI confirmation: "
            f"`python main.py plan save {value}`.",
        )
    if lowered.startswith("rollback plan "):
        parts = command.split()
        value = parts[2] if len(parts) >= 3 else ""
        if not value.isdigit():
            return RoutedCommandResult(False, "execution", "Plan ID must be a number.")
        return RoutedCommandResult(
            False,
            "execution",
            "Rollback requires direct CLI confirmation: "
            f"`python main.py plan rollback {value}`.",
        )
    if lowered.startswith("plan vlan "):
        return _route_plan_vlan(command)
    if lowered.startswith("plan cisco description "):
        return _route_plan_cisco_description(command)
    if lowered.startswith(("plan cisco access-port ", "plan cisco access port ")):
        return _route_plan_cisco_access_port(command)
    if lowered.startswith("plan mikrotik address "):
        return _route_plan_mikrotik_address(command)
    if lowered.startswith("plan mikrotik dhcp "):
        return _route_plan_mikrotik_dhcp(command)

    return RoutedCommandResult(
        False,
        "unsupported",
        "Unsupported chat command. Type `help` for supported commands.",
    )


def _scan_network() -> RoutedCommandResult:
    network_info = detect_local_network()
    validate_scan_target(network_info.cidr)
    result = scan_network(network_info.cidr)
    save_scan_result(result)
    return RoutedCommandResult(
        True,
        "scan",
        f"Scanned {result.network_info.cidr}; found {result.live_hosts_count} live host(s).",
        scan_result_to_dict(result),
    )


def _show_device(ip_address: str) -> RoutedCommandResult:
    device = get_device_profile(ip_address)
    if device is None:
        return RoutedCommandResult(False, "device", f"Device {ip_address} is not in inventory.")
    return RoutedCommandResult(True, "device", f"Device {ip_address} profile.", device_to_dict(device))


def _latest_report() -> RoutedCommandResult:
    report = get_latest_scan_report()
    scan = report.get("scan")
    data = {
        "scan": scan_run_to_dict(scan),
        "devices": report.get("devices", []),
        "network_info": report.get("network_info", {}),
    }
    message = "No latest scan report is stored." if scan is None else f"Latest scan: {scan.cidr}, {scan.live_hosts_count} live host(s)."
    return RoutedCommandResult(scan is not None, "report", message, data)


def _help() -> RoutedCommandResult:
    commands = [
        "show devices",
        "show device <ip>",
        "scan network",
        "nmap check",
        "nmap scan local",
        "nmap scan host <ip>",
        "nmap scan device <ip>",
        "enrich devices",
        "diagnose network",
        "diagnose management-ports",
        "diagnose gateway",
        "diagnose <ip>",
        "diagnose connectivity <ip>",
        "report latest",
        "build topology",
        "show topology",
        "export topology mermaid",
        "export topology mermaid to <path> (returns CLI instructions)",
        "topology report to <path> (returns CLI instructions)",
        "explain topology",
        "topology risk check plan <id>",
        "risk check plan <id>",
        "list snapshots",
        "show snapshot <id>",
        "snapshot restore guidance <id>",
        "export snapshot <id> (returns CLI instructions)",
        "list manual topology",
        "rebuild topology with manual",
        "knowledge list",
        "knowledge search <query>",
        "show knowledge <id>",
        "fetch docs vendor=<vendor> model=<model> url=<official-url> (returns CLI instructions)",
        "ask <question>",
        "summarize latest scan",
        "plan vlan device=<ip> vlan=<id> name=<name> ports=<range>",
        "plan cisco description device=<ip> interface=<iface> description=<text>",
        "plan cisco access-port device=<ip> interface=<iface> vlan=<id> description=<text>",
        "plan mikrotik address device=<ip> interface=<name> address=<cidr> comment=<text>",
        "plan mikrotik dhcp device=<ip> name=<name> interface=<iface> network=<cidr> gateway=<ip> pool-name=<name> pool-range=<start-end> dns=<ips> comment=<text>",
        "plans",
        "show plan <id>",
        "review plan <id>",
        "approve plan <id> (returns CLI confirmation instructions)",
        "reject plan <id> reason=<text>",
        "archive plan <id>",
        "preflight plan <id>",
        "preflight plan <id> refresh=true",
        "execute plan <id> (returns direct CLI confirmation instructions)",
        "save plan <id> (returns direct CLI confirmation instructions)",
        "rollback plan <id> (returns direct CLI confirmation instructions)",
        "exit",
    ]
    return RoutedCommandResult(True, "help", "Supported local chat commands.", {"commands": commands})


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _nmap_check() -> RoutedCommandResult:
    available = is_nmap_available()
    return RoutedCommandResult(
        True,
        "nmap",
        "nmap is available." if available else "nmap is optional and not installed. Install with: sudo apt install nmap",
        {"available": available, "version": get_nmap_version()},
    )


def _route_nmap_scan(command: str) -> RoutedCommandResult:
    parts = command.split()
    if len(parts) < 3:
        return RoutedCommandResult(False, "nmap", "Use: nmap scan local, nmap scan host <ip>, or nmap scan device <ip>.")
    mode = parts[2].lower()
    if mode == "local":
        target = detect_local_network().cidr
        profile = _profile_from_words(parts[3:])
    elif mode == "host" and len(parts) >= 4:
        target = parts[3]
        profile = _profile_from_words(parts[4:])
    elif mode == "device" and len(parts) >= 4:
        target = parts[3]
        profile = _profile_from_words(parts[4:])
        if get_device_profile(target) is None:
            return RoutedCommandResult(False, "nmap", f"Device {target} is not in inventory.")
    elif _looks_like_ip(mode):
        target = mode
        profile = _profile_from_words(parts[3:])
    else:
        return RoutedCommandResult(False, "nmap", "Use controlled nmap routes only. Raw nmap arguments are not accepted.")

    target = validate_nmap_target(target)
    profile = validate_nmap_profile(profile)
    result = run_nmap_scan(target, profile)
    save_nmap_results(result)
    return RoutedCommandResult(
        True,
        "nmap",
        f"Nmap {profile} scan saved {result.live_hosts_count} host(s).",
        _nmap_result_to_dict(result),
    )


def _profile_from_words(words: list[str]) -> str:
    text = " ".join(words).lower()
    if not text:
        return "common-ports"
    if "service" in text and "light" in text:
        return "service-light"
    if "ping" in text:
        return "ping"
    if "common" in text:
        return "common-ports"
    return text


def _nmap_result_to_dict(result) -> dict:
    return {
        "target": result.target,
        "profile": result.profile,
        "live_hosts_count": result.live_hosts_count,
        "devices": [device.model_dump(mode="json") for device in result.devices],
    }


def _route_plan_vlan(command: str) -> RoutedCommandResult:
    try:
        parts = shlex.split(command)
    except ValueError as exc:
        return RoutedCommandResult(False, "plan", f"Could not parse plan command: {exc}")
    values: dict[str, str] = {}
    for part in parts[2:]:
        if "=" not in part:
            return RoutedCommandResult(
                False,
                "plan",
                "Use key=value syntax. Example: plan vlan device=192.168.88.10 vlan=30 name=LAB ports=Gi0/5-Gi0/10",
            )
        key, value = part.split("=", 1)
        values[key.lower()] = value
    missing = [key for key in ("device", "vlan", "name") if key not in values]
    if missing:
        return RoutedCommandResult(False, "plan", f"Missing required values: {', '.join(missing)}")
    if not values["vlan"].isdigit():
        return RoutedCommandResult(False, "plan", "vlan must be a number.")
    result = create_vlan_plan(
        device_ip=values["device"],
        vlan_id=int(values["vlan"]),
        name=values["name"],
        ports=values.get("ports"),
    )
    return RoutedCommandResult(
        True,
        "plan",
        f"Created change plan #{result.plan.id}. PLAN ONLY -- NO COMMANDS EXECUTED.",
        change_plan_to_dict(result.plan),
    )


def _route_plan_cisco_description(command: str) -> RoutedCommandResult:
    values, error = _plan_key_values(command, skip=3)
    if error:
        return RoutedCommandResult(False, "plan", error)
    missing = [key for key in ("device", "interface", "description") if key not in values]
    if missing:
        return RoutedCommandResult(False, "plan", f"Missing required values: {', '.join(missing)}")
    result = create_cisco_description_plan(
        device_ip=values["device"],
        interface=values["interface"],
        description=values["description"],
    )
    return RoutedCommandResult(
        True,
        "plan",
        f"Created Cisco description plan #{result.plan.id}. PLAN ONLY -- NO COMMANDS EXECUTED.",
        change_plan_to_dict(result.plan),
    )


def _route_plan_cisco_access_port(command: str) -> RoutedCommandResult:
    try:
        parts = shlex.split(command)
    except ValueError as exc:
        return RoutedCommandResult(False, "plan", f"Could not parse Cisco access-port plan command: {exc}")
    skip = 4 if len(parts) >= 4 and parts[2].lower() == "access" and parts[3].lower() == "port" else 3
    values: dict[str, str] = {}
    for part in parts[skip:]:
        if "=" not in part:
            return RoutedCommandResult(
                False,
                "plan",
                "Use key=value syntax. Example: plan cisco access-port device=192.168.88.20 interface=Gi0/5 vlan=30 description=LAB-PC-01",
            )
        key, value = part.split("=", 1)
        values[key.lower()] = value
    missing = [key for key in ("device", "interface", "vlan") if key not in values]
    if missing:
        return RoutedCommandResult(False, "plan", f"Missing required values: {', '.join(missing)}")
    if not values["vlan"].isdigit():
        return RoutedCommandResult(False, "plan", "vlan must be a number.")
    result = create_cisco_access_port_plan(
        device_ip=values["device"],
        interface=values["interface"],
        vlan_id=int(values["vlan"]),
        description=values.get("description"),
    )
    return RoutedCommandResult(
        True,
        "plan",
        f"Created Cisco access-port plan #{result.plan.id}. PLAN ONLY -- NO COMMANDS EXECUTED.",
        change_plan_to_dict(result.plan),
    )


def _route_plan_mikrotik_address(command: str) -> RoutedCommandResult:
    try:
        parts = shlex.split(command)
    except ValueError as exc:
        return RoutedCommandResult(False, "plan", f"Could not parse MikroTik plan command: {exc}")
    values: dict[str, str] = {}
    for part in parts[3:]:
        if "=" not in part:
            return RoutedCommandResult(
                False,
                "plan",
                "Use key=value syntax. Example: plan mikrotik address device=192.168.88.1 interface=bridge address=192.168.50.1/24 comment=LAB",
            )
        key, value = part.split("=", 1)
        values[key.lower()] = value
    missing = [key for key in ("device", "interface", "address") if key not in values]
    if missing:
        return RoutedCommandResult(False, "plan", f"Missing required values: {', '.join(missing)}")
    result = create_mikrotik_address_plan(
        device_ip=values["device"],
        interface=values["interface"],
        address=values["address"],
        comment=values.get("comment"),
    )
    return RoutedCommandResult(
        True,
        "plan",
        f"Created MikroTik address plan #{result.plan.id}. PLAN ONLY -- NO COMMANDS EXECUTED.",
        change_plan_to_dict(result.plan),
    )


def _route_plan_mikrotik_dhcp(command: str) -> RoutedCommandResult:
    values, error = _plan_key_values(command, skip=3)
    if error:
        return RoutedCommandResult(False, "plan", error)
    missing = [key for key in ("device", "name", "interface", "network", "gateway", "pool-name", "pool-range") if key not in values]
    if missing:
        return RoutedCommandResult(False, "plan", f"Missing required values: {', '.join(missing)}")
    result = create_mikrotik_dhcp_plan(
        device_ip=values["device"],
        name=values["name"],
        interface=values["interface"],
        network=values["network"],
        gateway=values["gateway"],
        pool_name=values["pool-name"],
        pool_range=values["pool-range"],
        dns=values.get("dns"),
        comment=values.get("comment"),
    )
    return RoutedCommandResult(
        True,
        "plan",
        f"Created MikroTik DHCP plan #{result.plan.id}. PLAN ONLY -- NO COMMANDS EXECUTED.",
        change_plan_to_dict(result.plan),
    )


def _plan_key_values(command: str, skip: int) -> tuple[dict[str, str], str | None]:
    try:
        parts = shlex.split(command)
    except ValueError as exc:
        return {}, f"Could not parse plan command: {exc}"
    values: dict[str, str] = {}
    for part in parts[skip:]:
        if "=" not in part:
            return {}, "Use key=value syntax for plan commands."
        key, value = part.split("=", 1)
        values[key.lower()] = value
    return values, None


def _route_reject_plan(command: str) -> RoutedCommandResult:
    try:
        parts = shlex.split(command)
    except ValueError as exc:
        return RoutedCommandResult(False, "plan", f"Could not parse reject command: {exc}")
    if len(parts) < 3 or not parts[2].isdigit():
        return RoutedCommandResult(False, "plan", "Usage: reject plan <id> reason=<text>")
    values: dict[str, str] = {}
    for part in parts[3:]:
        if "=" in part:
            key, value = part.split("=", 1)
            values[key.lower()] = value
    plan = reject_change_plan(int(parts[2]), note=values.get("reason"))
    return RoutedCommandResult(True, "plan", f"Rejected plan {parts[2]}. NO COMMANDS EXECUTED.", change_plan_to_dict(plan))


def _route_preflight_plan(command: str) -> RoutedCommandResult:
    parts = command.split()
    if len(parts) < 3 or not parts[2].isdigit():
        return RoutedCommandResult(False, "plan", "Usage: preflight plan <id> [refresh=true]")
    refresh = any(part.lower() == "refresh=true" for part in parts[3:])
    result = run_preflight(int(parts[2]), refresh=refresh)
    return RoutedCommandResult(
        True,
        "preflight",
        f"Preflight {result.plan.preflight_status}. PREFLIGHT ONLY -- NO CONFIGURATION EXECUTED.",
        {
            "plan": change_plan_to_dict(result.plan),
            "findings": [finding.model_dump(mode="json") for finding in result.findings],
        },
    )


def _route_fetch_docs_instruction(command: str) -> RoutedCommandResult:
    try:
        parts = shlex.split(command)
    except ValueError as exc:
        return RoutedCommandResult(False, "knowledge", f"Could not parse fetch docs command: {exc}")
    values: dict[str, str] = {}
    for part in parts[2:]:
        if "=" in part:
            key, value = part.split("=", 1)
            values[key.lower()] = value
    url = values.get("url")
    vendor = values.get("vendor")
    model = values.get("model")
    if not url:
        return RoutedCommandResult(
            False,
            "knowledge",
            "Provide an explicit URL or use direct CLI: `python main.py knowledge fetch-url <url> --vendor <vendor> --model <model>`.",
        )
    if not vendor:
        return RoutedCommandResult(False, "knowledge", "vendor=<vendor> is required for documentation fetch instructions.")
    command_text = f"python main.py knowledge fetch-url {url} --vendor {vendor}"
    if model:
        command_text += f" --model {model}"
    return RoutedCommandResult(
        False,
        "knowledge",
        "Documentation fetching requires explicit CLI execution. Run: "
        f"`{command_text}`.",
    )
