from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.json import JSON
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from app.agent.action_log import log_agent_action, new_agent_session_id
from app.agent.agent_models import AgentResult, AgentToolResult, ParsedIntent, PolicyDecision
from app.agent.intent_parser import parse_intent
from app.agent.policy import evaluate_agent_action
from app.agent.session_memory import SessionMemory
from app.services.config_planner import create_cisco_access_port_plan, create_cisco_description_plan, create_mikrotik_address_plan, create_mikrotik_dhcp_plan, create_vlan_plan, get_change_plan, list_change_plans, review_change_plan, run_preflight
from app.services.config_snapshot import capture_manual_snapshot, generate_restore_guidance, list_snapshots, show_snapshot, write_snapshot_export_file
from app.services.device_connection import run_readonly_profile_collection
from app.services.diagnostics import diagnose_connectivity, diagnose_device, diagnose_management_ports, diagnose_network
from app.services.doc_fetcher import save_fetched_document_as_knowledge
from app.services.enrichment import enrich_stored_devices
from app.services.inventory import get_device_profile, get_latest_scan_report, list_devices, save_scan_result
from app.services.knowledge import get_knowledge, list_knowledge, search_knowledge
from app.services.lab_validation import lab_checklist, validate_lab_device, validate_lab_plan
from app.services.llm_planner import LLMPlanner
from app.services.manual_topology import add_manual_edge, add_manual_node, list_manual_edges, list_manual_nodes, list_manual_notes
from app.services.network_detection import detect_local_network
from app.services.nmap_tool import get_nmap_version, is_nmap_available, run_nmap_scan, save_nmap_results
from app.services.scanner import scan_network
from app.services.topology import build_topology_snapshot, explain_topology, export_topology_json, export_topology_mermaid, get_latest_topology, rebuild_topology_with_manual
from app.services.topology_awareness import analyze_plan_topology_risk
from app.services.topology_exporter import write_topology_export_file, write_topology_report_file


console = Console()


def run_agent(dry_policy: bool = False) -> None:
    memory = SessionMemory()
    session_id = new_agent_session_id()
    _banner(session_id, dry_policy=dry_policy)
    console.print("[green]Type `help` for commands. Type `exit` to leave.[/green]")
    while True:
        text = Prompt.ask("[bold green]na>[/bold green]").strip()
        if parse_intent(text, memory).tool_name == "exit":
            console.print("[green]Session closed.[/green]")
            return
        if parse_intent(text, memory).tool_name == "clear":
            console.clear()
            continue
        if not text:
            continue
        result = process_agent_input(text, memory, session_id=session_id, dry_policy=dry_policy)
        _print_result(result)


def process_agent_input(
    text: str,
    memory: SessionMemory,
    session_id: str,
    dry_policy: bool = False,
    confirm_fn=None,
) -> AgentResult:
    intent = parse_intent(text, memory)
    decision = evaluate_agent_action(intent.tool_name, intent.args)
    confirmation_result = "not_required"
    executed = False
    result: AgentResult | None = None
    error_message: str | None = None

    try:
        if not decision.allowed:
            result = AgentResult(
                intent.tool_name,
                decision.risk_level,
                False,
                decision.message,
                decision.direct_cli_command,
                policy_decision=_policy_label(decision),
            )
            return result

        if dry_policy:
            confirmation_result = "dry_policy"
            result = _dry_policy_result(intent, decision)
            return result

        if decision.requires_confirmation:
            confirmation_result = "confirmed" if _confirm(intent, decision, confirm_fn=confirm_fn) else "declined"
            if confirmation_result != "confirmed":
                result = AgentResult(intent.tool_name, decision.risk_level, False, "Action cancelled.", policy_decision=_policy_label(decision))
                return result

        result = execute_agent_intent(intent, memory, decision)
        result.policy_decision = _policy_label(decision)
        executed = True
        _update_memory(intent, result, memory)
        return result
    except Exception as exc:
        error_message = str(exc)
        result = AgentResult(intent.tool_name, decision.risk_level, False, str(exc), policy_decision=_policy_label(decision))
        return result
    finally:
        log_agent_action(
            session_id=session_id,
            user_input=text,
            intent=intent,
            decision=decision,
            confirmation_result=confirmation_result,
            executed=executed,
            result=result,
            error_message=error_message,
        )


def execute_agent_intent(intent: ParsedIntent, memory: SessionMemory, decision: PolicyDecision | None = None) -> AgentResult:
    decision = decision or evaluate_agent_action(intent.tool_name, intent.args)
    if not decision.allowed:
        return AgentResult(intent.tool_name, decision.risk_level, False, decision.message, decision.direct_cli_command)
    try:
        result = _execute_allowed_intent(intent, memory, decision.risk_level)
        _as_tool_result(result)
        return result
    except Exception as exc:
        return AgentResult(intent.tool_name, decision.risk_level, False, str(exc))


def _execute_allowed_intent(intent: ParsedIntent, memory: SessionMemory, risk: str) -> AgentResult:
    name = intent.tool_name
    args = intent.args
    if name == "help":
        return AgentResult(name, risk, True, "Supported agent actions are listed below.", data={"commands": _help_commands()})
    if name == "unknown":
        text = args.get("text") or intent.raw_text or ""
        return AgentResult(name, risk, False, _unknown_help(str(text)), data={"examples": _fallback_examples()})
    if name == "status":
        return AgentResult(name, risk, True, "Current in-memory session state.", data=memory.__dict__)
    if name == "show_devices":
        devices = list_devices()
        data = [{"ip": device.ip_address, "vendor": device.vendor_guess, "type": device.device_type_guess} for device in devices]
        return AgentResult(name, risk, True, f"{len(devices)} device(s) in inventory.", "python main.py device <ip>", data)
    if name == "show_device":
        ip = _require_arg(args, "ip")
        device = get_device_profile(ip)
        if device is None:
            return AgentResult(name, risk, False, f"Device {ip} is not in inventory.", "python main.py scan")
        return AgentResult(name, risk, True, f"Device {ip}: {device.vendor_guess} / {device.device_type_guess}.", f"python main.py device {ip}")
    if name == "latest_report":
        report = get_latest_scan_report()
        scan = report.get("scan")
        if scan is None:
            return AgentResult(name, risk, False, "No latest scan report is stored.", "python main.py scan")
        return AgentResult(name, risk, True, f"Latest scan: {scan.cidr}, {scan.live_hosts_count} live host(s).", "python main.py report")
    if name == "nmap_check":
        available = is_nmap_available()
        message = "nmap is available." if available else "nmap is optional and not installed. Install with: sudo apt install nmap"
        return AgentResult(name, risk, True, message, "nat nmap check", {"available": available, "version": get_nmap_version()})
    if name == "nmap_scan_local":
        target = detect_local_network().cidr
        profile = args.get("profile") or "common-ports"
        result = run_nmap_scan(target, str(profile))
        save_nmap_results(result)
        return AgentResult(name, risk, True, f"Nmap {result.profile} scan saved {result.live_hosts_count} host(s).", "nat devices", _nmap_result_data(result))
    if name == "nmap_scan_host":
        target = _require_arg(args, "target")
        profile = args.get("profile") or "common-ports"
        result = run_nmap_scan(target, str(profile))
        save_nmap_results(result)
        return AgentResult(name, risk, True, f"Nmap {result.profile} scan saved {result.live_hosts_count} host(s).", f"nat device {target}", _nmap_result_data(result))
    if name == "nmap_scan_device":
        target = _require_arg(args, "target")
        if get_device_profile(target) is None:
            return AgentResult(name, risk, False, f"Device {target} is not in inventory.", "nat devices")
        profile = args.get("profile") or "service-light"
        result = run_nmap_scan(target, str(profile))
        save_nmap_results(result)
        return AgentResult(name, risk, True, f"Nmap {result.profile} scan updated {target}.", f"nat device {target}", _nmap_result_data(result))
    if name == "scan_network":
        network = detect_local_network()
        scan = scan_network(network.cidr)
        save_scan_result(scan)
        return AgentResult(name, risk, True, f"Scanned {network.cidr}; found {scan.live_hosts_count} live host(s).", "python main.py devices")
    if name == "enrich_devices":
        devices = enrich_stored_devices()
        return AgentResult(name, risk, True, f"Enriched {len(devices)} stored device(s).", "python main.py devices")
    if name == "diagnose_network":
        result = diagnose_network()
        return AgentResult(name, risk, True, result.summary, result.suggested_commands[0] if result.suggested_commands else None)
    if name == "diagnose_device":
        ip = _require_arg(args, "ip")
        result = diagnose_device(ip)
        return AgentResult(name, risk, True, result.summary, result.suggested_commands[0] if result.suggested_commands else f"python main.py device {ip}")
    if name == "diagnose_management_ports":
        result = diagnose_management_ports()
        return AgentResult(name, risk, True, result.summary, result.suggested_commands[0] if result.suggested_commands else "python main.py devices")
    if name == "diagnose_connectivity":
        target = _require_arg(args, "target_ip")
        if target == "gateway":
            target = detect_local_network().gateway_ip
            if not target:
                return AgentResult(name, risk, False, "No gateway detected.")
        result = diagnose_connectivity(target)
        return AgentResult(name, risk, True, result.summary, result.suggested_commands[0] if result.suggested_commands else None)
    if name == "knowledge_list":
        items = list_knowledge()
        return AgentResult(name, risk, True, f"{len(items)} local knowledge document(s).", "python main.py knowledge search <query>")
    if name == "knowledge_show":
        item = get_knowledge(int(_require_arg(args, "knowledge_id")))
        if item is None:
            return AgentResult(name, risk, False, "Knowledge document not found.", "python main.py knowledge list")
        return AgentResult(name, risk, True, f"Knowledge #{item.id}: {item.title}", f"python main.py knowledge show {item.id}")
    if name == "knowledge_search":
        query = _require_arg(args, "query")
        results = search_knowledge(query)
        return AgentResult(name, risk, True, f"{len(results)} local knowledge result(s) for `{query}`.", "python main.py knowledge search \"...\"")
    if name == "ask":
        question = _require_arg(args, "question")
        answer = LLMPlanner().answer_question(question)
        return AgentResult(name, risk, True, answer, "python main.py ask \"...\"")
    if name == "list_plans":
        plans = list_change_plans()
        data = [{"id": plan.id, "type": plan.plan_type, "status": plan.status, "title": plan.title} for plan in plans]
        return AgentResult(name, risk, True, f"{len(plans)} saved change plan(s).", "python main.py plan show <id>", data)
    if name == "show_plan":
        plan_id = _require_plan_id(args)
        plan = get_change_plan(plan_id)
        if plan is None:
            return AgentResult(name, risk, False, f"Change plan {plan_id} not found.", "python main.py plan list")
        return AgentResult(name, risk, True, f"Plan #{plan.id}: {plan.title} [{plan.status}, preflight={plan.preflight_status}].", f"python main.py plan show {plan.id}")
    if name == "review_plan":
        plan_id = _require_plan_id(args)
        plan = review_change_plan(plan_id, note="Reviewed from agent mode")
        return AgentResult(name, risk, True, f"Reviewed plan #{plan.id}. REVIEW ONLY -- NO COMMANDS EXECUTED.", f"python main.py plan approve {plan.id}")
    if name in {"preflight_plan", "preflight_plan_refresh"}:
        plan_id = _require_plan_id(args)
        result = run_preflight(plan_id, refresh=name == "preflight_plan_refresh")
        return AgentResult(name, risk, True, f"Preflight {result.plan.preflight_status}. {result.plan.preflight_summary}", f"python main.py plan show {plan_id}")
    if name == "create_vlan_plan":
        result = create_vlan_plan(
            device_ip=_require_arg(args, "device"),
            vlan_id=int(_require_arg(args, "vlan")),
            name=_require_arg(args, "name"),
            ports=args.get("ports"),
        )
        return AgentResult(name, risk, True, f"Created Cisco VLAN plan #{result.plan.id}. PLAN ONLY -- NO COMMANDS EXECUTED.", f"python main.py plan show {result.plan.id}")
    if name == "create_cisco_description_plan":
        result = create_cisco_description_plan(
            device_ip=_require_arg(args, "device"),
            interface=_require_arg(args, "interface"),
            description=_require_arg(args, "description"),
        )
        return AgentResult(name, risk, True, f"Created Cisco description plan #{result.plan.id}. PLAN ONLY -- NO COMMANDS EXECUTED.", f"python main.py plan show {result.plan.id}")
    if name == "create_cisco_access_port_plan":
        result = create_cisco_access_port_plan(
            device_ip=_require_arg(args, "device"),
            interface=_require_arg(args, "interface"),
            vlan_id=int(_require_arg(args, "vlan")),
            description=args.get("description") or None,
        )
        return AgentResult(name, risk, True, f"Created Cisco access-port plan #{result.plan.id}. PLAN ONLY -- NO COMMANDS EXECUTED.", f"python main.py plan show {result.plan.id}")
    if name == "create_mikrotik_address_plan":
        result = create_mikrotik_address_plan(
            device_ip=_require_arg(args, "device"),
            interface=_require_arg(args, "interface"),
            address=_require_arg(args, "address"),
            comment=args.get("comment") or None,
        )
        return AgentResult(name, risk, True, f"Created MikroTik address plan #{result.plan.id}. PLAN ONLY -- NO COMMANDS EXECUTED.", f"python main.py plan show {result.plan.id}")
    if name == "create_mikrotik_dhcp_plan":
        result = create_mikrotik_dhcp_plan(
            device_ip=_require_arg(args, "device"),
            name=_require_arg(args, "name"),
            interface=_require_arg(args, "interface"),
            network=_require_arg(args, "network"),
            gateway=_require_arg(args, "gateway"),
            pool_name=_require_arg(args, "pool_name"),
            pool_range=_require_arg(args, "pool_range"),
            dns=args.get("dns") or None,
            comment=args.get("comment") or None,
        )
        return AgentResult(name, risk, True, f"Created MikroTik DHCP plan #{result.plan.id}. PLAN ONLY -- NO COMMANDS EXECUTED.", f"python main.py plan show {result.plan.id}")
    if name == "connect_collect":
        ip = _require_arg(args, "ip")
        result = run_readonly_profile_collection(ip)
        return AgentResult(name, risk, True, f"Read-only collection completed: {result.success_count} succeeded, {result.failure_count} failed.", f"python main.py command history {ip}")
    if name == "fetch_docs_url":
        result = save_fetched_document_as_knowledge(
            url=_require_arg(args, "url"),
            vendor=_require_arg(args, "vendor"),
            model=args.get("model") or None,
            doc_type=args.get("doc_type") or "vendor_note",
            trusted=bool(args.get("trusted", True)),
        )
        return AgentResult(name, risk, True, f"Saved fetched documentation as knowledge #{result.knowledge_id}.", f"python main.py knowledge show {result.knowledge_id}")
    if name == "lab_checklist":
        result = lab_checklist()
        return AgentResult(name, risk, True, result.summary, "python main.py lab validate-device <ip>")
    if name == "lab_validate_device":
        result = validate_lab_device(_require_arg(args, "ip"))
        return AgentResult(name, risk, True, result.summary, result.suggested_commands[0] if result.suggested_commands else None)
    if name == "lab_validate_plan":
        result = validate_lab_plan(_require_plan_id(args))
        return AgentResult(name, risk, True, result.summary, result.suggested_commands[0] if result.suggested_commands else None)
    if name == "workflow_scan_and_diagnose":
        network = detect_local_network()
        scan = scan_network(network.cidr)
        save_scan_result(scan)
        enriched = enrich_stored_devices()
        diagnostic = diagnose_network()
        topology = build_topology_snapshot()
        data = {
            "network": network.cidr,
            "live_hosts": scan.live_hosts_count,
            "enriched_devices": len(enriched),
            "topology_snapshot": topology.snapshot.id,
            "diagnostic_summary": diagnostic.summary,
        }
        return AgentResult(
            name,
            risk,
            True,
            f"Scanned {network.cidr}, found {scan.live_hosts_count} host(s), enriched {len(enriched)} device(s), built topology snapshot #{topology.snapshot.id}. {diagnostic.summary}",
            "nat diagnose network",
            data,
        )
    if name == "workflow_topology_report":
        manual_count = len(list_manual_nodes()) + len(list_manual_edges()) + len(list_manual_notes())
        result = rebuild_topology_with_manual() if manual_count else build_topology_snapshot()
        output = Path("reports") / f"topology_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        export = write_topology_report_file(output_path=str(output), force=False)
        return AgentResult(
            name,
            risk,
            True,
            f"Built topology snapshot #{result.snapshot.id} and wrote report to {export.output_path}.",
            f"nat topology show {result.snapshot.id}",
            {"output_path": export.output_path, "snapshot_id": result.snapshot.id, "manual_overlay": bool(manual_count)},
        )
    if name == "workflow_prepare_cisco_access_port":
        device = _arg_or_prompt(args, "device", "Device IP")
        interface = _arg_or_prompt(args, "interface", "Interface")
        vlan = _arg_or_prompt(args, "vlan", "VLAN ID")
        description = _arg_or_prompt(args, "description", "Description (optional)", default="")
        result = create_cisco_access_port_plan(
            device_ip=device,
            interface=interface,
            vlan_id=int(vlan),
            description=description or None,
        )
        return AgentResult(
            name,
            risk,
            True,
            f"Created Cisco access-port plan #{result.plan.id}. PLAN ONLY -- NO COMMANDS EXECUTED.",
            f"nat plan review {result.plan.id}",
            {"next_commands": _plan_next_commands(result.plan.id)},
        )
    if name == "workflow_prepare_mikrotik_dhcp":
        device = _arg_or_prompt(args, "device", "Device IP")
        dhcp_name = _arg_or_prompt(args, "name", "DHCP name")
        interface = _arg_or_prompt(args, "interface", "Interface")
        network = _arg_or_prompt(args, "network", "Network CIDR")
        gateway = _arg_or_prompt(args, "gateway", "Gateway IP")
        pool_name = _arg_or_prompt(args, "pool-name", "Pool name")
        pool_range = _arg_or_prompt(args, "pool-range", "Pool range")
        dns = _arg_or_prompt(args, "dns", "DNS comma-separated (optional)", default="")
        comment = _arg_or_prompt(args, "comment", "Comment (optional)", default="")
        result = create_mikrotik_dhcp_plan(
            device_ip=device,
            name=dhcp_name,
            interface=interface,
            network=network,
            gateway=gateway,
            pool_name=pool_name,
            pool_range=pool_range,
            dns=dns or None,
            comment=comment or None,
        )
        return AgentResult(
            name,
            risk,
            True,
            f"Created MikroTik DHCP plan #{result.plan.id}. PLAN ONLY -- NO COMMANDS EXECUTED.",
            f"nat plan review {result.plan.id}",
            {"next_commands": _plan_next_commands(result.plan.id)},
        )
    if name == "build_topology":
        result = build_topology_snapshot()
        return AgentResult(name, risk, True, f"Built topology snapshot #{result.snapshot.id}.", "python main.py topology show")
    if name == "show_topology":
        result = get_latest_topology()
        if result is None:
            return AgentResult(name, risk, False, "No topology snapshot exists.", "python main.py topology build")
        return AgentResult(name, risk, True, f"Topology snapshot #{result.snapshot.id}: {len(result.nodes)} node(s), {len(result.edges)} edge(s).", "python main.py topology explain")
    if name == "export_topology_json":
        data = export_topology_json()
        return AgentResult(name, risk, True, "Exported topology JSON.", "python main.py topology export --format json", data)
    if name == "export_topology_mermaid":
        text = export_topology_mermaid()
        return AgentResult(name, risk, True, text, "python main.py topology export --format mermaid")
    if name == "export_topology_file":
        result = write_topology_export_file(
            export_format=_require_arg(args, "format"),
            output_path=_require_arg(args, "output"),
            force=False,
        )
        return AgentResult(name, risk, True, f"Wrote {result.export_format} topology export to {result.output_path}.", f"python main.py topology show {result.snapshot_id}")
    if name == "topology_report_file":
        result = write_topology_report_file(output_path=_require_arg(args, "output"), force=False)
        return AgentResult(name, risk, True, f"Wrote topology report to {result.output_path}.", f"python main.py topology show {result.snapshot_id}")
    if name == "explain_topology":
        result = explain_topology()
        return AgentResult(name, risk, True, result.summary, result.suggested_commands[0] if result.suggested_commands else "python main.py topology show")
    if name == "topology_risk_check":
        plan_id = _require_plan_id(args)
        plan = get_change_plan(plan_id)
        if plan is None:
            return AgentResult(name, risk, False, f"Change plan {plan_id} not found.", "python main.py plan list")
        findings = analyze_plan_topology_risk(plan)
        data = [finding.model_dump(mode="json") for finding in findings]
        return AgentResult(name, risk, True, f"Topology risk check found {len(findings)} finding(s).", f"python main.py topology risk-check --plan-id {plan_id}", data)
    if name == "list_snapshots":
        snapshots = list_snapshots()
        data = [{"id": snapshot.id, "device": snapshot.device.ip_address if snapshot.device else None, "type": snapshot.snapshot_type, "plan_id": snapshot.plan_id} for snapshot in snapshots]
        return AgentResult(name, risk, True, f"{len(snapshots)} config snapshot(s).", "python main.py snapshot show <id>", data)
    if name == "show_snapshot":
        snapshot_id = int(_require_arg(args, "snapshot_id"))
        snapshot = show_snapshot(snapshot_id)
        if snapshot is None:
            return AgentResult(name, risk, False, f"Snapshot {snapshot_id} not found.", "python main.py snapshot list")
        return AgentResult(name, risk, True, f"Snapshot #{snapshot.id}: {snapshot.snapshot_type} for plan {snapshot.plan_id}.", f"python main.py snapshot show {snapshot.id}")
    if name == "snapshot_restore_guidance":
        snapshot_id = int(_require_arg(args, "snapshot_id"))
        guidance = generate_restore_guidance(snapshot_id)
        data = {
            "warnings": guidance.warnings,
            "recommended_steps": guidance.recommended_steps,
            "rollback_commands": guidance.rollback_commands,
        }
        return AgentResult(name, risk, True, guidance.summary, f"python main.py snapshot restore-guidance {snapshot_id}", data)
    if name == "export_snapshot_file":
        snapshot_id = int(_require_arg(args, "snapshot_id"))
        result = write_snapshot_export_file(
            snapshot_id=snapshot_id,
            export_format=_require_arg(args, "format"),
            output_path=_require_arg(args, "output"),
            force=False,
        )
        return AgentResult(name, risk, True, f"Wrote snapshot export to {result.output_path}.", f"python main.py snapshot show {snapshot_id}")
    if name == "capture_snapshot":
        plan_id = _require_plan_id(args)
        snapshot = capture_manual_snapshot(plan_id)
        return AgentResult(name, risk, True, f"Captured manual snapshot #{snapshot.id}.", f"python main.py snapshot show {snapshot.id}")
    if name == "list_manual_topology":
        nodes = list_manual_nodes()
        edges = list_manual_edges()
        notes = list_manual_notes()
        return AgentResult(
            name,
            risk,
            True,
            f"Manual topology: {len(nodes)} node(s), {len(edges)} edge(s), {len(notes)} note(s).",
            "python main.py topology rebuild-with-manual",
        )
    if name == "add_manual_topology_node":
        result = add_manual_node(
            node_key=_require_arg(args, "key"),
            label=_require_arg(args, "label"),
            node_type=_require_arg(args, "type"),
            ip_address=args.get("ip"),
            mac_address=args.get("mac"),
            vendor=args.get("vendor"),
            notes=args.get("notes"),
        )
        return AgentResult(name, risk, True, result.message, "python main.py topology rebuild-with-manual")
    if name == "add_manual_topology_edge":
        result = add_manual_edge(
            source_node_key=_require_arg(args, "source"),
            target_node_key=_require_arg(args, "target"),
            relation_type=args.get("relation") or "manual",
            label=args.get("label"),
            confidence=args.get("confidence") or "high",
            notes=args.get("notes"),
        )
        message = result.message
        if result.warnings:
            message += " Warnings: " + "; ".join(result.warnings)
        return AgentResult(name, risk, True, message, "python main.py topology rebuild-with-manual")
    if name == "rebuild_topology_with_manual":
        result = rebuild_topology_with_manual()
        return AgentResult(name, risk, True, f"Built topology snapshot #{result.snapshot.id} with manual corrections.", "python main.py topology show")
    return AgentResult(name, risk, False, "Unsupported agent command. Type `help` for examples.")


def _confirm(intent: ParsedIntent, decision: PolicyDecision, confirm_fn=None) -> bool:
    console.print(
        Panel.fit(
            f"This action is medium risk: {intent.tool_name}\nReason: {decision.message}",
            title="Confirmation Required",
            border_style="yellow",
        )
    )
    if confirm_fn is not None:
        return bool(confirm_fn(intent, decision))
    return Confirm.ask("Proceed?", default=False)


def _dry_policy_result(intent: ParsedIntent, decision: PolicyDecision) -> AgentResult:
    policy = _policy_label(decision)
    return AgentResult(
        intent.tool_name,
        decision.risk_level,
        True,
        (
            "DRY POLICY MODE -- NO TOOL EXECUTED\n"
            f"Intent: {intent.tool_name}\n"
            f"Tool: {intent.tool_name}\n"
            f"Risk: {decision.risk_level}\n"
            f"Policy: {policy}\n"
            "Execution: skipped because --dry-policy is enabled"
        ),
        policy_decision=policy,
    )


def _print_result(result: AgentResult) -> None:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold green")
    table.add_column()
    table.add_row("Action:", result.action)
    table.add_row("Risk:", result.risk_level)
    table.add_row("Policy:", result.policy_decision or "allowed")
    table.add_row("Result:", result.message)
    if result.next_command:
        table.add_row("Next:", result.next_command)
    console.print(Panel(table, title="Network Assistant Agent", border_style="green" if result.ok else "yellow", expand=False))
    if result.data:
        compact = json.dumps(result.data, indent=2, default=str)
        if len(compact) > 3000:
            compact = compact[:3000] + "\n... truncated ..."
        console.print(JSON(compact))


def _update_memory(intent: ParsedIntent, result: AgentResult, memory: SessionMemory) -> None:
    if not result.ok:
        return
    if "ip" in intent.args and intent.args["ip"]:
        memory.last_device_ip = str(intent.args["ip"])
        memory.last_diagnostic_target = str(intent.args["ip"])
    if "target_ip" in intent.args and intent.args["target_ip"] not in {None, "gateway"}:
        memory.last_device_ip = str(intent.args["target_ip"])
        memory.last_diagnostic_target = str(intent.args["target_ip"])
    if "target" in intent.args and intent.args["target"]:
        memory.last_device_ip = str(intent.args["target"])
        memory.last_diagnostic_target = str(intent.args["target"])
    if "plan_id" in intent.args and intent.args["plan_id"]:
        memory.last_plan_id = int(intent.args["plan_id"])
    if result.action in {
        "create_vlan_plan",
        "create_cisco_description_plan",
        "create_cisco_access_port_plan",
        "create_mikrotik_address_plan",
        "create_mikrotik_dhcp_plan",
        "workflow_prepare_cisco_access_port",
        "workflow_prepare_mikrotik_dhcp",
    } and result.next_command:
        try:
            memory.last_plan_id = int(result.next_command.rsplit(" ", 1)[-1])
        except ValueError:
            pass
    if result.action == "scan_network":
        memory.last_scan_summary = result.message
    if result.action == "knowledge_search":
        memory.last_knowledge_query = str(intent.args.get("query", ""))


def _require_arg(args: dict, key: str) -> str:
    value = args.get(key)
    if value is None or value == "":
        raise ValueError(f"Missing required argument `{key}`.")
    return str(value)


def _arg_or_prompt(args: dict, key: str, prompt: str, default: str | None = None) -> str:
    value = args.get(key)
    if value is not None and value != "":
        return str(value)
    if default is not None:
        return Prompt.ask(prompt, default=default)
    return Prompt.ask(prompt)


def _require_plan_id(args: dict) -> int:
    value = args.get("plan_id")
    if value is None:
        raise ValueError("Missing required plan id.")
    return int(value)


def _plan_next_commands(plan_id: int) -> list[str]:
    return [
        f"nat plan review {plan_id}",
        f"nat plan approve {plan_id}",
        f"nat plan preflight {plan_id} --refresh",
        f"nat plan execute {plan_id} --dry-run",
    ]


def _unknown_help(text: str) -> str:
    return (
        f"I did not understand: {text or '--'}\n"
        "Try:\n"
        + "\n".join(f"- {example}" for example in _fallback_examples())
    )


def _fallback_examples() -> list[str]:
    return [
        "scan my network",
        "diagnose network",
        "show devices",
        "build topology",
        "workflow scan and diagnose",
        "prepare mikrotik dhcp",
        "ask summarize latest scan",
    ]


def _banner(session_id: str, dry_policy: bool = False) -> None:
    body = f"NETWORK ASSISTANT AGENT\nSession: {session_id}"
    if dry_policy:
        body += "\nDRY POLICY MODE -- NO TOOL EXECUTED"
    console.print(Panel.fit(body, border_style="green"))


def _policy_label(decision: PolicyDecision) -> str:
    if decision.direct_cli_required:
        return "direct_cli_required"
    if not decision.allowed:
        return "blocked"
    if decision.requires_confirmation:
        return "requires_confirmation"
    return "allowed"


def _as_tool_result(result: AgentResult) -> AgentToolResult:
    suggested = [result.next_command] if result.next_command else []
    return AgentToolResult(
        success=result.ok,
        title=result.action,
        summary=result.message,
        details={"data": result.data} if result.data else {},
        suggested_commands=suggested,
        next_actions=suggested,
    )


def _help_commands() -> dict[str, list[str]]:
    return {
        "Inventory": ["show devices", "show device 192.168.88.1", "latest report", "scan my network", "enrich devices"],
        "Nmap": ["nmap check", "nmap scan local", "nmap scan local service light", "nmap scan 192.168.88.1", "nmap scan device 192.168.88.1"],
        "Diagnostics": ["diagnose network", "inspect 192.168.88.1", "diagnose connectivity 192.168.88.1", "show risky management ports"],
        "Topology": ["build topology", "show topology", "explain topology", "topology risk check plan 1", "export topology mermaid"],
        "Knowledge": ["knowledge search routeros ssh", "knowledge list", "ask summarize latest scan"],
        "Planning": [
            "plans",
            "show plan 1",
            "preflight plan 1",
            "plan cisco access-port device=192.168.88.20 interface=Gi0/5 vlan=30 description=LAB-PC-01",
            "plan mikrotik dhcp device=192.168.88.1 name=lab-dhcp interface=bridge network=192.168.50.0/24 gateway=192.168.50.1 pool-name=lab-pool pool-range=192.168.50.100-192.168.50.200",
        ],
        "Workflows": [
            "workflow scan and diagnose",
            "workflow topology report",
            "prepare cisco access port",
            "prepare mikrotik dhcp",
        ],
        "Blocked high-risk actions": [
            "execute plan 1",
            "save plan 1",
            "rollback plan 1",
            "Execution/save/rollback require direct CLI exact confirmation.",
        ],
    }


def _nmap_result_data(result) -> dict:
    return {
        "target": result.target,
        "profile": result.profile,
        "live_hosts_count": result.live_hosts_count,
        "devices": [device.model_dump(mode="json") for device in result.devices],
    }
