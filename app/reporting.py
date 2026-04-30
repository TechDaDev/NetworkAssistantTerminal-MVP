from __future__ import annotations

from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from app.models import (
    AgentActionLog,
    ChangePlan,
    CommandRun,
    Device,
    DeviceConfigSnapshot,
    DeviceCredential,
    DeviceKnowledge,
    ExecutionLog,
    ManualTopologyEdge,
    ManualTopologyNode,
    ManualTopologyNote,
)
from app.services.device_connection import (
    CommandResult,
    ConnectionTestResult,
    DeviceProfileCollectionResult,
)
from app.services.lab_validation import LabValidationResult
from app.services.manual_topology import ManualTopologyOperationResult
from app.services.topology_exporter import TopologyFileExportResult
from app.services.topology import TopologyBuildResult, TopologySnapshotResult
from app.services.config_planner import findings_for_plan
from app.services.config_executor import ExecutionResult
from app.services.config_snapshot import SnapshotExportResult, SnapshotRestoreGuidance
from app.services.doc_fetcher import SavedFetchedDocument
from app.services.knowledge import KnowledgeSearchResult, search_knowledge
from app.services.lab_integration import IntegrationHarnessResult
from app.services.nmap_tool import NmapScanResult, get_nmap_version, is_nmap_available
from app.services.custom_plan_generator import metadata_for_plan
from app.release import ReleaseCommandResult
from app.schemas import DiagnosticResult, NetworkInfo, ScanResult


console = Console()


def _format_dt(value: datetime | None) -> str:
    if value is None:
        return "--"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def print_network_info(network_info: NetworkInfo) -> None:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold")
    table.add_column()
    table.add_row("Interface:", network_info.interface_name)
    table.add_row("Local IP:", network_info.local_ip)
    table.add_row("Subnet:", network_info.netmask)
    table.add_row("CIDR:", network_info.cidr)
    table.add_row("Gateway:", network_info.gateway_ip or "--")
    table.add_row("MAC:", network_info.mac_address or "--")
    table.add_row("Private Network:", "Yes" if network_info.is_private else "No")
    table.add_row("Safe To Scan:", "Yes" if network_info.safe_to_scan else "No")
    console.print(Panel(table, title="Detected Network", expand=False))


def _ports_text(device: Device) -> str:
    ports = sorted(port.port for port in device.ports if port.state == "open")
    return ",".join(str(port) for port in ports) if ports else "--"


def print_scan_summary(scan_result: ScanResult) -> None:
    elapsed = (scan_result.finished_at - scan_result.started_at).total_seconds()
    console.print(Panel.fit(
        f"CIDR: {scan_result.network_info.cidr}\n"
        f"Live Hosts: {scan_result.live_hosts_count}\n"
        f"Scan Time: {elapsed:.1f} seconds",
        title="Scan Summary",
    ))

    table = Table(title="Discovered Devices")
    table.add_column("IP")
    table.add_column("MAC")
    table.add_column("Vendor Guess")
    table.add_column("Open Ports")
    table.add_column("Type Guess")
    for device in scan_result.devices:
        open_ports = ",".join(str(port.port) for port in device.ports) or "--"
        table.add_row(
            device.host.ip_address,
            device.host.mac_address or "--",
            device.fingerprint.vendor_guess,
            open_ports,
            device.fingerprint.type_guess,
        )
    console.print(table)


def print_nmap_check() -> None:
    import shutil

    available = is_nmap_available()
    path = shutil.which("nmap")
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold")
    table.add_column()
    table.add_row("Available:", "Yes" if available else "No")
    table.add_row("Path:", path or "--")
    table.add_row("Version:", get_nmap_version() or "--")
    if not available:
        table.add_row("Install:", "sudo apt install nmap")
    console.print(Panel(table, title="Nmap Availability", expand=False))


def print_nmap_scan_result(result: NmapScanResult, saved: bool = True) -> None:
    elapsed = (result.finished_at - result.started_at).total_seconds()
    console.print(Panel.fit(
        f"Target: {result.target}\n"
        f"Profile: {result.profile}\n"
        f"Live Hosts: {result.live_hosts_count}\n"
        f"Scan Time: {elapsed:.1f} seconds\n"
        f"Saved Inventory: {'Yes' if saved else 'No'}",
        title="Nmap Scan Summary",
    ))

    hosts = Table(title="Nmap Hosts")
    hosts.add_column("IP")
    hosts.add_column("Hostname")
    hosts.add_column("MAC")
    hosts.add_column("Open Ports")
    for device in result.devices:
        hosts.add_row(
            device.host.ip_address,
            device.host.hostname or "--",
            device.host.mac_address or "--",
            ",".join(str(port.port) for port in device.ports) or "--",
        )
    console.print(hosts)

    ports = Table(title="Nmap Open Ports And Services")
    ports.add_column("IP")
    ports.add_column("Port")
    ports.add_column("Protocol")
    ports.add_column("Service")
    for device in result.devices:
        for port in sorted(device.ports, key=lambda item: item.port):
            ports.add_row(device.host.ip_address, str(port.port), port.protocol, port.service_guess)
    console.print(ports)


def print_devices_table(devices: list[Device]) -> None:
    table = Table(title="Stored Devices")
    table.add_column("IP")
    table.add_column("Hostname")
    table.add_column("MAC")
    table.add_column("Vendor")
    table.add_column("Type")
    table.add_column("Open Ports")
    table.add_column("Last Seen")
    for device in devices:
        table.add_row(
            device.ip_address,
            device.hostname or "--",
            device.mac_address or "--",
            device.vendor_guess,
            device.device_type_guess,
            _ports_text(device),
            _format_dt(device.last_seen),
        )
    console.print(table)


def print_device_profile(device: Device | None) -> None:
    if device is None:
        print_error("Device not found in local inventory.")
        return

    model = _latest_observation(device, "manual_model") or "--"
    overview = Table.grid(padding=(0, 2))
    overview.add_column(style="bold")
    overview.add_column()
    overview.add_row("IP:", device.ip_address)
    overview.add_row("Hostname:", device.hostname or "--")
    overview.add_row("MAC:", device.mac_address or "--")
    overview.add_row("Vendor:", device.vendor_guess)
    overview.add_row("Model:", model)
    overview.add_row("Type:", device.device_type_guess)
    overview.add_row("Confidence:", device.confidence)
    overview.add_row("Last Seen:", _format_dt(device.last_seen))
    console.print(Panel(overview, title="Device Profile", expand=False))

    ports = Table(title="Open Ports")
    ports.add_column("Port")
    ports.add_column("Protocol")
    ports.add_column("Service")
    ports.add_column("Last Seen")
    for port in sorted(device.ports, key=lambda item: item.port):
        ports.add_row(str(port.port), port.protocol, port.service_guess, _format_dt(port.last_seen))
    console.print(ports)

    credentials = Table(title="Credentials")
    credentials.add_column("Type")
    credentials.add_column("Username")
    credentials.add_column("Platform")
    credentials.add_column("Port")
    credentials.add_column("Status")
    credentials.add_column("Last Success")
    for credential in sorted(device.credentials, key=lambda item: item.updated_at, reverse=True):
        credentials.add_row(
            credential.connection_type,
            credential.username,
            credential.platform_hint,
            str(credential.port),
            credential.status,
            _format_dt(credential.last_success_at),
        )
    console.print(credentials)

    command_runs = Table(title="Recent Command Runs")
    command_runs.add_column("Started")
    command_runs.add_column("Command")
    command_runs.add_column("Success")
    command_runs.add_column("Preview")
    for run in sorted(device.command_runs, key=lambda item: item.started_at, reverse=True)[:5]:
        command_runs.add_row(
            _format_dt(run.started_at),
            run.command,
            "Yes" if run.success else "No",
            _preview(run.output if run.success else run.error_message or ""),
        )
    console.print(command_runs)

    observations = Table(title="Observations")
    observations.add_column("Type")
    observations.add_column("Value")
    observations.add_column("Source")
    observations.add_column("Confidence")
    observations.add_column("Created")
    for observation in sorted(device.observations, key=lambda item: item.created_at, reverse=True):
        observations.add_row(
            observation.observation_type,
            observation.observation_value,
            observation.source,
            observation.confidence,
            _format_dt(observation.created_at),
        )
    console.print(observations)

    query_parts = [part for part in [device.vendor_guess, model if model != "--" else None, device.device_type_guess] if part and part != "Unknown"]
    if query_parts:
        related = search_knowledge(" ".join(query_parts), limit=5)
        if related:
            knowledge = Table(title="Related Local Knowledge")
            knowledge.add_column("ID")
            knowledge.add_column("Title")
            knowledge.add_column("Doc Type")
            knowledge.add_column("Trusted")
            for result in related:
                item = result.item
                knowledge.add_row(str(item.id), item.title, item.doc_type, "Yes" if item.is_trusted else "No")
            console.print(knowledge)


def print_enrichment_summary(devices: list[Device]) -> None:
    table = Table(title="Enriched Devices")
    table.add_column("IP")
    table.add_column("Vendor")
    table.add_column("Type")
    table.add_column("Confidence")
    table.add_column("Recent Observations")
    for device in devices:
        recent = sorted(device.observations, key=lambda item: item.created_at, reverse=True)[:4]
        table.add_row(
            device.ip_address,
            device.vendor_guess,
            device.device_type_guess,
            device.confidence,
            ", ".join(f"{item.observation_type}={item.observation_value}" for item in recent) or "--",
        )
    console.print(table)


def print_knowledge_results(items: list[DeviceKnowledge]) -> None:
    print_knowledge_list(items, title="Knowledge Search Results")


def print_knowledge_list(items: list[DeviceKnowledge], title: str = "Local Knowledge") -> None:
    table = Table(title=title)
    table.add_column("ID")
    table.add_column("Vendor")
    table.add_column("Model")
    table.add_column("Doc Type")
    table.add_column("Title")
    table.add_column("Tags")
    table.add_column("Trusted")
    table.add_column("Updated")
    for item in items:
        table.add_row(
            str(item.id),
            item.vendor or "--",
            item.model or "--",
            item.doc_type,
            item.title,
            item.tags or "--",
            "Yes" if item.is_trusted else "No",
            _format_dt(item.updated_at),
        )
    console.print(table)


def print_knowledge_added(item: DeviceKnowledge) -> None:
    console.print(
        Panel.fit(
            f"ID: {item.id}\nTitle: {item.title}\nVendor: {item.vendor or '--'}\nModel: {item.model or '--'}",
            title="Knowledge Added",
        )
    )


def print_knowledge_document(item: DeviceKnowledge | None) -> None:
    if item is None:
        print_error("Knowledge document not found.")
        return
    summary = (
        f"ID: {item.id}\n"
        f"Title: {item.title}\n"
        f"Vendor: {item.vendor or '--'}\n"
        f"Model: {item.model or '--'}\n"
        f"Device Type: {item.device_type or '--'}\n"
        f"Doc Type: {item.doc_type}\n"
        f"Tags: {item.tags or '--'}\n"
        f"Trusted: {'Yes' if item.is_trusted else 'No'}\n"
        f"Source: {item.source_name or item.source_url or item.source_type}\n"
        f"Updated: {_format_dt(item.updated_at)}"
    )
    console.print(Panel(summary, title="Knowledge Document", border_style="green", expand=False))
    console.print(Panel(item.content, title="Content", border_style="green", expand=False))


def print_knowledge_search_results(results: list[KnowledgeSearchResult]) -> None:
    table = Table(title="Knowledge Search Results")
    table.add_column("ID")
    table.add_column("Title")
    table.add_column("Vendor/Model")
    table.add_column("Doc Type")
    table.add_column("Rank")
    table.add_column("Preview")
    for result in results:
        item = result.item
        rank = f"{result.rank:.4f}" if result.rank is not None else "--"
        table.add_row(
            str(item.id),
            item.title,
            f"{item.vendor or '--'} / {item.model or '--'}",
            item.doc_type,
            rank,
            result.preview or _preview(item.content, length=160),
        )
    console.print(table)


def print_fetched_document_saved(result: SavedFetchedDocument) -> None:
    body = (
        f"Knowledge ID: {result.knowledge_id}\n"
        f"Title: {result.document.title}\n"
        f"Source URL: {result.document.url}\n"
        f"Official Source: {'Yes' if result.document.official else 'No'}\n"
        f"DeepSeek Summary: {'Yes' if result.summarized else 'No'}"
    )
    if result.warning:
        body += f"\nWarning: {result.warning}"
    console.print(Panel(body, title="Fetched Documentation Saved", border_style="green", expand=False))


def print_credential_list(credentials: list[DeviceCredential]) -> None:
    table = Table(title="Stored Credentials")
    table.add_column("IP")
    table.add_column("Username")
    table.add_column("Type")
    table.add_column("Platform")
    table.add_column("Port")
    table.add_column("Status")
    table.add_column("Last Success")
    for credential in credentials:
        table.add_row(
            credential.device.ip_address,
            credential.username,
            credential.connection_type,
            credential.platform_hint,
            str(credential.port),
            credential.status,
            _format_dt(credential.last_success_at),
        )
    console.print(table)


def print_connection_test(result: ConnectionTestResult) -> None:
    status = "Success" if result.success else "Failed"
    console.print(
        Panel.fit(
            f"IP: {result.ip_address}\nPlatform: {result.platform}\nStatus: {status}\nMessage: {result.message}",
            title="Connection Test",
        )
    )


def print_command_result(result: CommandResult) -> None:
    status = "Success" if result.success else "Failed"
    warning = "\nSensitive read-only output was saved locally." if result.sensitive else ""
    body = (
        f"IP: {result.ip_address}\n"
        f"Command: {result.command}\n"
        f"Status: {status}\n"
        f"Started: {_format_dt(result.started_at)}\n"
        f"Finished: {_format_dt(result.finished_at)}{warning}"
    )
    if result.error_message:
        body += f"\nError: {result.error_message}"
    console.print(Panel.fit(body, title="Command Run"))
    if result.output:
        console.print(Panel(_preview(result.output, length=1200), title="Output Preview", expand=False))


def print_collection_result(result: DeviceProfileCollectionResult) -> None:
    console.print(
        Panel.fit(
            f"IP: {result.ip_address}\n"
            f"Platform: {result.platform}\n"
            f"Successful Commands: {result.success_count}\n"
            f"Failed Commands: {result.failure_count}",
            title="Profile Collection",
        )
    )
    table = Table(title="Collection Commands")
    table.add_column("Command")
    table.add_column("Success")
    table.add_column("Preview/Error")
    for command_result in result.command_results:
        table.add_row(
            command_result.command,
            "Yes" if command_result.success else "No",
            _preview(command_result.output if command_result.success else command_result.error_message or ""),
        )
    console.print(table)


def print_command_history(runs: list[CommandRun]) -> None:
    table = Table(title="Command History")
    table.add_column("Timestamp")
    table.add_column("Command")
    table.add_column("Success")
    table.add_column("Preview/Error")
    for run in runs:
        table.add_row(
            _format_dt(run.started_at),
            run.command,
            "Yes" if run.success else "No",
            _preview(run.output if run.success else run.error_message or ""),
        )
    console.print(table)


def print_latest_report(report_data: dict) -> None:
    if not report_data:
        print_warning("No scan data found. Run `python main.py scan` first.")
        return

    scan = report_data["scan"]
    devices: list[dict] = report_data["devices"]
    inventory_devices: list[Device] = report_data.get("inventory_devices", [])

    gateway = next(
        (device for device in devices if device["host"]["ip_address"] == scan.gateway_ip),
        None,
    )
    management_ports = []
    for device in devices:
        ip_address = device["host"]["ip_address"]
        for port in device.get("ports", []):
            if port["port"] in {22, 23, 80, 443, 8080, 8443, 8291, 8728, 8729, 161}:
                management_ports.append(
                    f"{ip_address}:{port['port']} ({port['service_guess']})"
                )

    summary = (
        f"Scan Timestamp: {_format_dt(scan.finished_at)}\n"
        f"Detected Network: {scan.cidr}\n"
        f"Total Live Hosts: {scan.live_hosts_count}\n"
        f"Router/Gateway Candidate: {gateway['host']['ip_address'] if gateway else scan.gateway_ip or '--'}"
    )
    console.print(Panel.fit(summary, title="Latest Scan Report"))

    table = Table(title="Device Categories")
    table.add_column("Category")
    table.add_column("Count")
    table.add_column("Devices")
    categories = {
        "Possible switches/routers": [
            d for d in devices
            if "Router" in d["fingerprint"]["type_guess"]
            or "Network" in d["fingerprint"]["type_guess"]
        ],
        "Possible servers": [
            d for d in devices
            if any(p["port"] in {22, 80, 443, 445, 3389} for p in d.get("ports", []))
        ],
        "Possible client devices": [
            d for d in devices
            if d["fingerprint"]["type_guess"] in {"Windows Host or Server", "Unknown"}
        ],
        "Unknown devices": [
            d for d in devices if d["fingerprint"]["type_guess"] == "Unknown"
        ],
    }
    for label, category_devices in categories.items():
        table.add_row(
            label,
            str(len(category_devices)),
            ", ".join(d["host"]["ip_address"] for d in category_devices) or "--",
        )
    console.print(table)

    console.print(Panel.fit(
        "\n".join(management_ports) if management_ports else "No common management ports detected.",
        title="Open Management Ports",
    ))
    observation_lines = []
    for device in inventory_devices:
        recent = sorted(device.observations, key=lambda item: item.created_at, reverse=True)[:3]
        if recent:
            facts = ", ".join(f"{item.observation_type}={item.observation_value}" for item in recent)
            observation_lines.append(f"{device.ip_address}: {facts}")
    console.print(Panel.fit(
        "\n".join(observation_lines) if observation_lines else "No enriched observations yet. Run `python main.py enrich`.",
        title="Enriched Observations",
    ))
    console.print(Panel.fit(
        "DeepSeek reasoning is read-only in Phase 4. It can summarize stored local data, "
        "but it cannot scan, connect to devices, run commands, ask for credentials, "
        "or change configuration.",
        title="Safety Notes",
    ))


def print_llm_answer(question: str, answer: str) -> None:
    console.print(
        Panel.fit(
            f"Question: {question}",
            title="Network Assistant",
            border_style="green",
        )
    )
    console.print(
        Panel(
            answer,
            title="DeepSeek Analysis",
            border_style="green",
            expand=False,
        )
    )


def print_llm_context(context: str) -> None:
    console.print(
        Panel(
            context,
            title="Redacted LLM Context",
            border_style="green",
            expand=False,
        )
    )


def print_diagnostic_result(result: DiagnosticResult) -> None:
    console.print(
        Panel.fit(
            result.summary,
            title=result.title,
            border_style="green",
        )
    )

    findings = Table(title="Findings")
    findings.add_column("Severity")
    findings.add_column("Finding")
    findings.add_column("Detail")
    findings.add_column("Recommendation")
    for finding in result.findings:
        evidence = f"\nEvidence: {'; '.join(finding.evidence)}" if finding.evidence else ""
        findings.add_row(
            finding.severity,
            finding.title,
            finding.detail + evidence,
            finding.recommendation or "--",
        )
    console.print(findings)

    if result.suggested_commands:
        commands = "\n".join(f"{index}. {command}" for index, command in enumerate(result.suggested_commands, start=1))
        console.print(Panel.fit(commands, title="Suggested Manual Commands", border_style="green"))


def print_change_plan(plan: ChangePlan) -> None:
    console.print(
        Panel.fit(
            "PLAN ONLY -- NO COMMANDS EXECUTED",
            title=f"Change Plan #{plan.id}",
            border_style="yellow",
        )
    )
    summary = (
        f"Title: {plan.title}\n"
        f"Device: {plan.device.ip_address if plan.device else '--'}\n"
        f"Type: {plan.plan_type}\n"
        f"Risk: {plan.risk_level}\n"
        f"Status: {plan.status}\n"
        f"Preflight: {plan.preflight_status}\n"
        f"Preflight Checked: {_format_dt(plan.preflight_checked_at)}\n"
        f"Preflight Summary: {plan.preflight_summary or '--'}\n"
        f"Created: {_format_dt(plan.created_at)}\n"
        f"Description: {plan.description}"
    )
    console.print(Panel(summary, title="Plan Summary", border_style="green", expand=False))

    findings = findings_for_plan(plan)
    table = Table(title="Validation Findings")
    table.add_column("Severity")
    table.add_column("Finding")
    table.add_column("Detail")
    table.add_column("Recommendation")
    for finding in findings:
        evidence = f"\nEvidence: {'; '.join(finding.evidence)}" if finding.evidence else ""
        table.add_row(
            finding.severity,
            finding.title,
            finding.detail + evidence,
            finding.recommendation or "--",
        )
    console.print(table)

    history = Table(title="Approval History")
    history.add_column("Action")
    history.add_column("Note")
    history.add_column("Created")
    for log in sorted(plan.approval_logs, key=lambda item: _sort_dt(item.created_at)):
        history.add_row(log.action, log.note or "--", _format_dt(log.created_at))
    console.print(history)
    console.print(Panel(Text(plan.proposed_commands or "--"), title="Proposed Commands", border_style="green", expand=False))
    console.print(Panel(Text(plan.rollback_commands or "--"), title="Rollback Commands", border_style="yellow", expand=False))
    if plan.plan_type in {"custom_routeros_plan", "custom_cisco_plan"}:
        metadata = metadata_for_plan(plan)
        custom_summary = (
            f"Generated By: {metadata.get('generated_by', 'deepseek')}\n"
            f"Platform: {metadata.get('platform', '--')}\n"
            f"Task: {metadata.get('task_summary', plan.title)}\n"
            f"Policy: {metadata.get('policy_summary') or '--'}\n"
            f"Risk: {metadata.get('risk_summary') or '--'}\n"
            f"Double Confirmation Required: {'Yes' if metadata.get('requires_double_confirmation') else 'No'}\n"
            "Backup Required: Yes"
        )
        console.print(Panel(custom_summary, title="Custom Plan Governance", border_style="yellow", expand=False))
        console.print(Panel(Text("\n".join(metadata.get("precheck_commands", [])) or "--"), title="Precheck Commands", border_style="green", expand=False))
        console.print(Panel(Text("\n".join(metadata.get("verification_commands", [])) or "--"), title="Verification Commands", border_style="green", expand=False))
        warnings = metadata.get("warnings", [])
        if warnings:
            console.print(Panel(Text("\n".join(str(item) for item in warnings)), title="Warnings", border_style="yellow", expand=False))
    try:
        from app.services.topology_awareness import analyze_plan_topology_risk

        topology_findings = analyze_plan_topology_risk(plan)
    except Exception:
        topology_findings = []
    if topology_findings:
        print_topology_risk_findings(plan.id, topology_findings)
    if plan.plan_type.startswith("mikrotik"):
        if plan.plan_type == "mikrotik_dhcp_server":
            message = (
                "MIKROTIK DHCP PLAN\n"
                "DHCP execution is supported only after approval + preflight passed + exact confirmation.\n"
                "RouterOS applies DHCP changes immediately.\n"
                "No separate save step is available.\n"
                "Rollback is available if needed."
            )
        else:
            message = (
                "MIKROTIK ROUTEROS PLAN\n"
                "RouterOS changes are applied immediately after execution.\n"
                "No separate save step is available.\n"
                "Rollback command is available if needed."
            )
        console.print(
            Panel.fit(
                message,
                title="MikroTik Boundary",
                border_style="yellow",
            )
        )
    if plan.plan_type in {"cisco_interface_description", "cisco_access_port"}:
        warning = (
            "CISCO INTERFACE PLAN\n"
            "Execution supported only after approval + preflight passed + exact confirmation.\n"
            "Rollback is basic and may not restore previous state if it was unknown."
        )
        if plan.plan_type == "cisco_access_port":
            warning += "\nChanging access VLAN can disconnect attached clients if used incorrectly."
        console.print(Panel.fit(warning, title="Cisco Interface Boundary", border_style="yellow"))
    latest_verification = _latest_log_status(plan, {"verified", "verification_failed"})
    latest_save = _latest_log_status(plan, {"save_success", "save_failed"})
    latest_execution = _latest_log_status(
        plan,
        {"success", "failed", "rolled_back", "rollback_failed", "manual_rollback_success", "manual_rollback_failed"},
    )
    operations = (
        f"Latest Execution: {latest_execution or '--'}\n"
        f"Latest Verification: {latest_verification or '--'}\n"
        f"Config Saved: {'Yes' if latest_save == 'save_success' or plan.status == 'saved' else 'No'}\n"
        f"Rollback Available: {'Yes' if bool(plan.rollback_commands.strip()) else 'No'}"
    )
    console.print(Panel(operations, title="Execution State", border_style="green", expand=False))
    console.print(
        Panel.fit(
            "APPROVAL ONLY -- NO COMMANDS EXECUTED\nAPPROVED DOES NOT MEAN EXECUTED",
            title="Lifecycle Warning",
            border_style="yellow",
        )
    )


def print_preflight_result(plan: ChangePlan, findings: list[DiagnosticFinding]) -> None:
    message = "PREFLIGHT ONLY -- NO CONFIGURATION EXECUTED"
    if plan.plan_type == "mikrotik_dhcp_server":
        message = (
            "MIKROTIK DHCP PREFLIGHT\n"
            "Preflight only. No DHCP commands were executed.\n"
            "DHCP execution is not supported yet."
        )
    console.print(
        Panel.fit(
            message,
            title=f"Preflight Plan #{plan.id}",
            border_style="yellow",
        )
    )
    console.print(
        Panel.fit(
            f"Status: {plan.preflight_status}\nChecked: {_format_dt(plan.preflight_checked_at)}\nSummary: {plan.preflight_summary or '--'}",
            title="Preflight Summary",
            border_style="green",
        )
    )
    table = Table(title="Preflight Findings")
    table.add_column("Severity")
    table.add_column("Finding")
    table.add_column("Detail")
    table.add_column("Recommendation")
    for finding in findings:
        evidence = f"\nEvidence: {'; '.join(finding.evidence)}" if finding.evidence else ""
        table.add_row(
            finding.severity,
            finding.title,
            finding.detail + evidence,
            finding.recommendation or "--",
        )
    console.print(table)


def print_topology_risk_findings(plan_id: int, findings: list[DiagnosticFinding]) -> None:
    console.print(
        Panel.fit(
            "TOPOLOGY RISK CHECK -- NO NETWORK COMMANDS EXECUTED",
            title=f"Plan #{plan_id}",
            border_style="yellow",
        )
    )
    table = Table(title="Topology-Aware Warnings")
    table.add_column("Severity")
    table.add_column("Finding")
    table.add_column("Detail")
    table.add_column("Recommendation")
    for finding in findings:
        evidence = f"\nEvidence: {'; '.join(finding.evidence)}" if finding.evidence else ""
        table.add_row(
            finding.severity,
            finding.title,
            finding.detail + evidence,
            finding.recommendation or "--",
        )
    if not findings:
        table.add_row("info", "No topology-aware warnings", "No topology risks were found from local evidence.", "--")
    console.print(table)


def print_execution_result(result: ExecutionResult) -> None:
    title = f"Execution Plan #{result.plan.id}"
    if result.dry_run:
        warning = "DRY RUN ONLY -- NO COMMANDS EXECUTED"
    elif result.plan.plan_type == "mikrotik_dhcp_server":
        warning = (
            "MIKROTIK DHCP EXECUTION\n"
            "RouterOS applies DHCP changes immediately.\n"
            "No separate save step is available.\n"
            "Rollback is available if needed."
        )
    elif result.plan.plan_type == "mikrotik_address":
        warning = "MIKROTIK EXECUTION"
    elif result.log and result.log.status in {"verified", "verification_failed"}:
        warning = "VERIFY ONLY -- READ-ONLY COMMANDS EXECUTED"
    elif result.log and result.log.status in {"save_success", "save_failed"}:
        warning = "SAVE OPERATION RESULT"
    elif result.log and result.log.status in {"manual_rollback_success", "manual_rollback_failed"}:
        warning = "MANUAL ROLLBACK RESULT"
    else:
        warning = "CONFIGURATION EXECUTION RESULT"
    console.print(Panel.fit(warning, title=title, border_style="red" if not result.dry_run else "yellow"))
    log_lines = [
        f"Message: {result.message}",
        f"Plan Status: {result.plan.status}",
        f"Dry Run: {'Yes' if result.dry_run else 'No'}",
    ]
    if result.log is not None:
        log_lines.extend(
            [
                f"Execution Log ID: {result.log.id}",
                f"Execution Status: {result.log.status}",
                f"Started: {_format_dt(result.log.started_at)}",
                f"Finished: {_format_dt(result.log.finished_at)}",
            ]
        )
        if result.log.error_message:
            log_lines.append(f"Error: {result.log.error_message}")
    console.print(Panel("\n".join(log_lines), title="Execution Summary", border_style="green", expand=False))
    console.print(Panel(Text("\n".join(result.proposed_commands) or "--"), title="Proposed Commands", border_style="green", expand=False))
    console.print(Panel(Text("\n".join(result.rollback_commands) or "--"), title="Rollback Commands", border_style="yellow", expand=False))
    if result.log and result.log.post_check_output:
        console.print(Panel(_preview(result.log.post_check_output, length=1200), title="Verification Output Preview", border_style="green", expand=False))
    if result.log and result.log.execution_output:
        console.print(Panel(_preview(result.log.execution_output, length=1200), title="Operation Output Preview", border_style="green", expand=False))
    if result.log and result.log.rollback_output:
        console.print(Panel(_preview(result.log.rollback_output, length=1200), title="Rollback Output Preview", border_style="yellow", expand=False))
    console.print(
        Panel.fit(
            "RouterOS applies changes immediately. Use rollback if the result is wrong."
            if result.plan.plan_type in {"mikrotik_address", "mikrotik_dhcp_server"}
            else "No running-config or startup-config save was performed.",
            title="Persistence Note",
            border_style="yellow",
        )
    )


def print_execution_history(logs: list[ExecutionLog]) -> None:
    table = Table(title="Execution History")
    table.add_column("ID")
    table.add_column("Plan")
    table.add_column("Device")
    table.add_column("Status")
    table.add_column("Started")
    table.add_column("Finished")
    table.add_column("Error")
    for log in logs:
        table.add_row(
            str(log.id),
            str(log.plan_id),
            log.device.ip_address if log.device else "--",
            log.status,
            _format_dt(log.started_at),
            _format_dt(log.finished_at),
            _preview(log.error_message or "", length=80),
        )
    console.print(table)


def print_snapshot_list(snapshots: list[DeviceConfigSnapshot]) -> None:
    table = Table(title="Config Snapshots")
    table.add_column("ID")
    table.add_column("Device")
    table.add_column("Plan")
    table.add_column("Execution Log")
    table.add_column("Type")
    table.add_column("Platform")
    table.add_column("Created")
    table.add_column("Commands")
    for snapshot in snapshots:
        commands = _snapshot_command_names(snapshot)
        table.add_row(
            str(snapshot.id),
            snapshot.device.ip_address if snapshot.device else "--",
            str(snapshot.plan_id) if snapshot.plan_id is not None else "--",
            str(snapshot.execution_log_id) if snapshot.execution_log_id is not None else "--",
            snapshot.snapshot_type,
            snapshot.platform or "--",
            _format_dt(snapshot.created_at),
            str(len(commands)),
        )
    console.print(table)


def print_snapshot_detail(snapshot: DeviceConfigSnapshot | None, full: bool = False) -> None:
    if snapshot is None:
        print_error("Config snapshot not found.")
        return
    commands = _snapshot_command_names(snapshot)
    body = (
        f"ID: {snapshot.id}\n"
        f"Device: {snapshot.device.ip_address if snapshot.device else snapshot.device_id}\n"
        f"Plan ID: {snapshot.plan_id if snapshot.plan_id is not None else '--'}\n"
        f"Execution Log ID: {snapshot.execution_log_id if snapshot.execution_log_id is not None else '--'}\n"
        f"Type: {snapshot.snapshot_type}\n"
        f"Platform: {snapshot.platform or '--'}\n"
        f"Created: {_format_dt(snapshot.created_at)}\n"
        f"Commands Captured: {len(commands)}"
    )
    console.print(Panel(body, title="Config Snapshot", border_style="green", expand=False))
    if commands:
        console.print(Panel("\n".join(commands), title="Captured Commands", border_style="green", expand=False))
    content = snapshot.content or ""
    if not full:
        content = _preview(content, length=2000)
    console.print(Panel(Text(content or "--"), title="Snapshot Content" + ("" if full else " Preview"), border_style="yellow", expand=False))


def print_snapshot_export_result(result: SnapshotExportResult) -> None:
    body = (
        f"Snapshot ID: {result.snapshot_id}\n"
        f"Format: {result.export_format}\n"
        f"Output: {result.output_path}\n"
        f"Bytes: {result.bytes_written}"
    )
    console.print(Panel(body, title="Snapshot Export", border_style="green", expand=False))


def print_snapshot_restore_guidance(guidance: SnapshotRestoreGuidance) -> None:
    console.print(
        Panel(
            f"Snapshot ID: {guidance.snapshot_id}\nPlatform: {guidance.platform}\n{guidance.summary}",
            title=guidance.title,
            border_style="green",
            expand=False,
        )
    )
    if guidance.warnings:
        console.print(Panel("\n".join(f"- {item}" for item in guidance.warnings), title="Warnings", border_style="yellow", expand=False))
    if guidance.rollback_commands:
        console.print(Panel(Text("\n".join(guidance.rollback_commands)), title="Linked Plan Rollback Commands", border_style="yellow", expand=False))
    if guidance.recommended_steps:
        console.print(Panel("\n".join(f"{index}. {step}" for index, step in enumerate(guidance.recommended_steps, start=1)), title="Recommended Manual Steps", border_style="green", expand=False))


def _snapshot_command_names(snapshot: DeviceConfigSnapshot) -> list[str]:
    try:
        import json

        data = json.loads(snapshot.command_outputs_json or "{}")
    except Exception:
        return []
    return list(data.keys()) if isinstance(data, dict) else []


def print_lab_checklist(result: LabValidationResult) -> None:
    print_lab_validation_result(result)


def print_lab_validation_result(result: LabValidationResult) -> None:
    console.print(Panel.fit(result.summary, title=result.title, border_style="green"))
    table = Table(title="Lab Checks")
    table.add_column("Status")
    table.add_column("Check")
    table.add_column("Detail")
    table.add_column("Recommendation")
    for check in result.checks:
        table.add_row(
            check.status,
            check.name,
            check.detail,
            check.recommendation or "--",
        )
    console.print(table)
    if result.suggested_commands:
        console.print(
            Panel(
                Text("\n".join(result.suggested_commands)),
                title="Suggested Manual Commands",
                border_style="yellow",
                expand=False,
            )
        )


def print_lab_integration_result(result: IntegrationHarnessResult) -> None:
    console.print(Panel.fit(result.summary, title=result.title, border_style="green"))
    table = Table(title="Integration Harness Checks")
    table.add_column("Status")
    table.add_column("Check")
    table.add_column("Detail")
    table.add_column("Recommendation")
    for check in result.checks:
        table.add_row(check.status, check.name, check.detail, check.recommendation or "--")
    console.print(table)
    if result.suggested_commands:
        console.print(
            Panel(
                Text("\n".join(result.suggested_commands)),
                title="Suggested Commands",
                border_style="yellow",
                expand=False,
            )
        )


def print_release_result(result: ReleaseCommandResult) -> None:
    console.print(Panel.fit(result.summary, title=result.title, border_style="green"))
    table = Table(title=result.title)
    table.add_column("Status")
    table.add_column("Check")
    table.add_column("Detail")
    table.add_column("Recommendation")
    for check in result.checks:
        table.add_row(check.status, check.name, check.detail, check.recommendation or "--")
    console.print(table)
    if result.suggested_commands:
        console.print(Panel(Text("\n".join(result.suggested_commands)), title="Suggested Commands", border_style="yellow", expand=False))


def print_safe_config(data: dict[str, object], title: str = "Safe Config") -> None:
    table = Table(title=title)
    table.add_column("Key")
    table.add_column("Value")
    for key, value in data.items():
        table.add_row(str(key), str(value))
    console.print(table)


def print_agent_logs(logs: list[AgentActionLog]) -> None:
    table = Table(title="Agent Action Logs")
    table.add_column("ID")
    table.add_column("Session")
    table.add_column("Tool")
    table.add_column("Risk")
    table.add_column("Policy")
    table.add_column("Executed")
    table.add_column("Success")
    table.add_column("Created")
    table.add_column("Summary")
    for log in logs:
        table.add_row(
            str(log.id),
            log.session_id,
            log.tool_name,
            log.risk_level,
            log.policy_decision,
            "Yes" if log.executed else "No",
            "Yes" if log.success else "No",
            _format_dt(log.created_at),
            _preview(log.result_summary, length=80),
        )
    console.print(table)


def print_agent_log_detail(log: AgentActionLog | None) -> None:
    if log is None:
        print_error("Agent action log not found.")
        return
    body = (
        f"ID: {log.id}\n"
        f"Session: {log.session_id}\n"
        f"Created: {_format_dt(log.created_at)}\n"
        f"Tool: {log.tool_name}\n"
        f"Risk: {log.risk_level}\n"
        f"Policy: {log.policy_decision}\n"
        f"Confirmation Required: {'Yes' if log.confirmation_required else 'No'}\n"
        f"Confirmation Result: {log.confirmation_result}\n"
        f"Executed: {'Yes' if log.executed else 'No'}\n"
        f"Success: {'Yes' if log.success else 'No'}\n"
        f"Result: {log.result_summary or '--'}\n"
        f"Error: {log.error_message or '--'}"
    )
    console.print(Panel(body, title=f"Agent Log #{log.id}", border_style="green", expand=False))
    console.print(Panel(log.user_input or "--", title="User Input", border_style="yellow", expand=False))
    console.print(Panel(log.parsed_intent or "--", title="Parsed Intent", border_style="green", expand=False))


def print_topology_build_result(result: TopologyBuildResult) -> None:
    summary = {}
    try:
        import json

        summary = json.loads(result.snapshot.summary_json or "{}")
    except Exception:
        summary = {}
    body = (
        f"Snapshot ID: {result.snapshot.id}\n"
        f"Nodes: {summary.get('node_count', '--')}\n"
        f"Edges: {summary.get('edge_count', '--')}\n"
        f"Confidence: {summary.get('edge_confidence', {})}\n"
        f"Warnings: {len(result.warnings)}"
    )
    console.print(Panel(body, title="Topology Build", border_style="green", expand=False))
    if result.warnings:
        console.print(Panel("\n".join(result.warnings), title="Warnings", border_style="yellow", expand=False))


def print_topology_snapshot(result: TopologySnapshotResult | None) -> None:
    if result is None:
        print_warning("No topology snapshot exists. Run `python main.py topology build` first.")
        return
    console.print(
        Panel.fit(
            f"Snapshot: {result.snapshot.id}\nCreated: {_format_dt(result.snapshot.created_at)}\nNodes: {len(result.nodes)}\nEdges: {len(result.edges)}",
            title="Topology Snapshot",
            border_style="green",
        )
    )
    nodes = Table(title="Topology Nodes")
    nodes.add_column("Key")
    nodes.add_column("Label")
    nodes.add_column("Type")
    nodes.add_column("IP")
    nodes.add_column("Vendor")
    nodes.add_column("Confidence")
    for node in result.nodes:
        nodes.add_row(node.node_key, node.label, node.node_type, node.ip_address or "--", node.vendor, node.confidence)
    console.print(nodes)
    edges = Table(title="Topology Edges")
    edges.add_column("Source")
    edges.add_column("Target")
    edges.add_column("Relation")
    edges.add_column("Confidence")
    edges.add_column("Evidence Source")
    for edge in result.edges:
        edges.add_row(edge.source_node_key, edge.target_node_key, edge.relation_type, edge.confidence, edge.evidence_source)
    console.print(edges)


def print_topology_explanation(result: DiagnosticResult) -> None:
    print_diagnostic_result(result)


def print_topology_export(text: str, export_format: str) -> None:
    console.print(Panel(Text(text), title=f"Topology Export ({export_format})", border_style="green", expand=False))


def print_topology_file_export(result: TopologyFileExportResult) -> None:
    body = (
        f"Output: {result.output_path}\n"
        f"Format: {result.export_format}\n"
        f"Snapshot: {result.snapshot_id}\n"
        f"Bytes: {result.bytes_written}"
    )
    console.print(Panel(body, title="Topology File Export", border_style="green", expand=False))


def print_manual_topology_nodes(nodes: list[ManualTopologyNode]) -> None:
    table = Table(title="Manual Topology Nodes")
    table.add_column("ID")
    table.add_column("Key")
    table.add_column("Label")
    table.add_column("Type")
    table.add_column("IP")
    table.add_column("Vendor")
    table.add_column("Notes")
    for node in nodes:
        table.add_row(
            str(node.id),
            node.node_key,
            node.label,
            node.node_type,
            node.ip_address or "--",
            node.vendor or "--",
            (node.notes or "--")[:80],
        )
    console.print(table)


def print_manual_topology_edges(edges: list[ManualTopologyEdge]) -> None:
    table = Table(title="Manual Topology Edges")
    table.add_column("ID")
    table.add_column("Source")
    table.add_column("Target")
    table.add_column("Relation")
    table.add_column("Confidence")
    table.add_column("Label")
    table.add_column("Notes")
    for edge in edges:
        table.add_row(
            str(edge.id),
            edge.source_node_key,
            edge.target_node_key,
            edge.relation_type,
            edge.confidence,
            edge.label or "--",
            (edge.notes or "--")[:80],
        )
    console.print(table)


def print_manual_topology_notes(notes: list[ManualTopologyNote]) -> None:
    table = Table(title="Manual Topology Notes")
    table.add_column("ID")
    table.add_column("Target Type")
    table.add_column("Target Key")
    table.add_column("Note")
    table.add_column("Created")
    for note in notes:
        table.add_row(str(note.id), note.target_type, note.target_key or "--", note.note[:100], _format_dt(note.created_at))
    console.print(table)


def print_manual_topology_operation_result(result: ManualTopologyOperationResult) -> None:
    console.print(Panel(result.message, title="Manual Topology", border_style="green" if result.success else "yellow", expand=False))
    if result.warnings:
        console.print(Panel("\n".join(result.warnings), title="Warnings", border_style="yellow", expand=False))


def print_change_plan_list(plans: list[ChangePlan]) -> None:
    table = Table(title="Change Plans")
    table.add_column("ID")
    table.add_column("Device")
    table.add_column("Type")
    table.add_column("Title")
    table.add_column("Risk")
    table.add_column("Status")
    table.add_column("Created")
    for plan in plans:
        table.add_row(
            str(plan.id),
            plan.device.ip_address if plan.device else "--",
            plan.plan_type,
            plan.title,
            plan.risk_level,
            plan.status,
            _format_dt(plan.created_at),
        )
    console.print(table)


def _latest_observation(device: Device, observation_type: str) -> str | None:
    matches = [
        observation
        for observation in device.observations
        if observation.observation_type == observation_type
    ]
    if not matches:
        return None
    return max(matches, key=lambda item: item.created_at).observation_value


def _preview(value: str, length: int = 120) -> str:
    compact = " ".join(value.split())
    if len(compact) <= length:
        return compact or "--"
    return compact[: length - 3] + "..."


def _sort_dt(value: datetime | None) -> datetime:
    if value is None:
        return datetime.min
    if value.tzinfo is not None:
        return value.replace(tzinfo=None)
    return value


def _latest_log_status(plan: ChangePlan, statuses: set[str]) -> str | None:
    logs = [log for log in plan.execution_logs if log.status in statuses]
    if not logs:
        return None
    return max(logs, key=lambda item: _sort_dt(item.started_at)).status


def print_error(message: str) -> None:
    console.print(f"[bold red]Error:[/bold red] {message}")


def print_warning(message: str) -> None:
    console.print(f"[bold yellow]Warning:[/bold yellow] {message}")
