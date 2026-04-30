import typer

from app.agent.agent_loop import run_agent
from app.chat import run_chat
from app.command_policy import CommandPolicyError
from app.reporting import (
    print_agent_log_detail,
    print_agent_logs,
    print_collection_result,
    print_command_history,
    print_command_result,
    print_connection_test,
    print_credential_list,
    print_change_plan,
    print_change_plan_list,
    print_device_profile,
    print_devices_table,
    print_enrichment_summary,
    print_error,
    print_execution_history,
    print_execution_result,
    print_fetched_document_saved,
    print_knowledge_added,
    print_knowledge_document,
    print_knowledge_list,
    print_knowledge_results,
    print_knowledge_search_results,
    print_lab_integration_result,
    print_lab_checklist,
    print_lab_validation_result,
    print_latest_report,
    print_llm_answer,
    print_llm_context,
    print_manual_topology_edges,
    print_manual_topology_nodes,
    print_manual_topology_notes,
    print_manual_topology_operation_result,
    print_diagnostic_result,
    print_preflight_result,
    print_network_info,
    print_nmap_check,
    print_nmap_scan_result,
    print_scan_summary,
    print_release_result,
    print_safe_config,
    print_snapshot_detail,
    print_snapshot_export_result,
    print_snapshot_list,
    print_snapshot_restore_guidance,
    print_topology_build_result,
    print_topology_explanation,
    print_topology_file_export,
    print_topology_export,
    print_topology_risk_findings,
    print_topology_snapshot,
)
from app.llm_policy import LLMSafetyError
from app.llm_policy import validate_llm_question
from app.safety import UnsafeNetworkError, validate_scan_target
from app.services.credentials import (
    CredentialError,
    delete_device_credential,
    list_device_credentials,
    save_device_credential,
)
from app.services.config_planner import (
    ConfigPlanError,
    approval_warnings,
    approve_change_plan,
    archive_change_plan,
    create_cisco_access_port_plan,
    create_cisco_description_plan,
    create_mikrotik_address_plan,
    create_mikrotik_dhcp_plan,
    create_vlan_plan,
    get_change_plan,
    list_change_plans,
    run_preflight,
    reject_change_plan,
    review_change_plan,
)
from app.services.config_executor import (
    ConfigExecutionError,
    execute_change_plan,
    get_execution_history,
    rollback_change_plan,
    save_plan_config,
    verify_change_plan,
)
from app.services.custom_plan_executor import DOUBLE_CONFIRMATION_PHRASE, custom_plan_requires_double_confirmation
from app.services.custom_plan_generator import (
    CustomPlanError,
    generate_custom_plan_from_goal,
    save_custom_plan,
)
from app.services.config_snapshot import (
    ConfigSnapshotError,
    capture_manual_snapshot,
    generate_restore_guidance,
    list_snapshots,
    write_snapshot_export_file,
    show_snapshot,
)
from app.services.device_connection import (
    DeviceConnectionError,
    command_history,
    run_readonly_command,
    run_readonly_profile_collection,
    test_connection,
)
from app.services.doc_fetcher import (
    DocFetchError,
    save_fetched_document_as_knowledge,
    search_official_docs,
)
from app.services.diagnostics import (
    DiagnosticError,
    diagnose_connectivity,
    diagnose_device,
    diagnose_management_ports,
    diagnose_network,
)
from app.services.enrichment import enrich_stored_devices
from app.services.inventory import (
    get_device_profile,
    get_latest_scan_report,
    list_devices,
    reset_database,
    save_scan_result,
    update_device_profile,
)
from app.services.knowledge import (
    KnowledgeError,
    SUPPORTED_DOC_TYPES,
    add_knowledge,
    delete_knowledge,
    get_knowledge,
    import_knowledge_file,
    list_knowledge,
    search_knowledge,
)
from app.services.lab_validation import lab_checklist, validate_lab_device, validate_lab_plan
from app.services.lab_integration import integration_check, integration_report
from app.services.manual_topology import (
    ManualTopologyError,
    add_manual_edge,
    add_manual_node,
    add_manual_note,
    delete_manual_edge,
    delete_manual_node,
    delete_manual_note,
    list_manual_edges,
    list_manual_nodes,
    list_manual_notes,
)
from app.agent.action_log import get_agent_log, list_agent_logs
from app.services.topology import (
    build_topology_snapshot,
    explain_topology,
    export_topology_json,
    export_topology_mermaid,
    get_latest_topology,
    get_topology,
    rebuild_topology_with_manual,
)
from app.services.topology_exporter import (
    TopologyExportError,
    write_topology_export_file,
    write_topology_report_file,
)
from app.services.topology_awareness import analyze_plan_topology_risk
from app.services.context_builder import build_local_network_context
from app.services.llm_planner import LLMPlanner, LLMPlannerError
from app.services.network_detection import NetworkDetectionError, detect_local_network
from app.services.nmap_tool import run_nmap_scan, save_nmap_results, validate_nmap_profile, validate_nmap_target
from app.services.scanner import scan_network
from app.services.security import CredentialSecurityError, generate_credential_key
from app.release import config_paths, doctor as release_doctor, init_project, safe_config, v1_readiness, version_text


app = typer.Typer(help="Network Assistant terminal MVP.")
knowledge_app = typer.Typer(help="Local reusable device knowledge.")
security_app = typer.Typer(help="Local security helpers.")
credentials_app = typer.Typer(help="Encrypted local device credentials.")
connect_app = typer.Typer(help="Read-only SSH connection helpers.")
command_app = typer.Typer(help="Read-only allowlisted command execution.")
diagnose_app = typer.Typer(help="Guided diagnostic workflows.")
plan_app = typer.Typer(help="Configuration plan lifecycle and controlled execution.")
lab_app = typer.Typer(help="Safe lab validation helpers.")
agent_app = typer.Typer(help="Interactive deterministic network operations agent.", invoke_without_command=True)
agent_logs_app = typer.Typer(help="Agent action audit logs.", invoke_without_command=True)
topology_app = typer.Typer(help="Read-only evidence-based topology mapping.")
snapshot_app = typer.Typer(help="Read-only device config snapshots.")
config_app = typer.Typer(help="Show safe local configuration.")
release_app = typer.Typer(help="Release readiness checks.")
nmap_app = typer.Typer(help="Controlled optional nmap scanner.")
manual_node_app = typer.Typer(help="Manual local topology node corrections.")
manual_edge_app = typer.Typer(help="Manual local topology edge corrections.")
manual_note_app = typer.Typer(help="Manual local topology notes.")
app.add_typer(knowledge_app, name="knowledge")
app.add_typer(security_app, name="security")
app.add_typer(credentials_app, name="credentials")
app.add_typer(connect_app, name="connect")
app.add_typer(command_app, name="command")
app.add_typer(diagnose_app, name="diagnose")
app.add_typer(plan_app, name="plan")
app.add_typer(lab_app, name="lab")
app.add_typer(agent_app, name="agent")
agent_app.add_typer(agent_logs_app, name="logs")
app.add_typer(topology_app, name="topology")
app.add_typer(snapshot_app, name="snapshot")
app.add_typer(config_app, name="config")
app.add_typer(release_app, name="release")
app.add_typer(nmap_app, name="nmap")
topology_app.add_typer(manual_node_app, name="manual-node")
topology_app.add_typer(manual_edge_app, name="manual-edge")
topology_app.add_typer(manual_note_app, name="manual-note")


@app.command()
def version() -> None:
    """Show Network Assistant version."""
    typer.echo(version_text())


@app.command()
def init(force: bool = typer.Option(False, "--force", help="Overwrite .env from .env.example before generating a key.")) -> None:
    """Initialize local data directory, .env, credential key, and SQLite tables."""
    if force:
        print_error("--force will overwrite the existing .env before generating a new missing key.")
    print_release_result(init_project(force=force))


@app.command()
def doctor() -> None:
    """Run local release-readiness checks without network access."""
    print_release_result(release_doctor())


@config_app.command("show")
def config_show() -> None:
    """Show safe configuration values without secrets."""
    print_safe_config(safe_config(), title="Network Assistant Config")


@config_app.command("paths")
def config_paths_command() -> None:
    """Show project paths used by Network Assistant."""
    print_safe_config(config_paths(), title="Network Assistant Paths")


@release_app.command("readiness")
def release_readiness() -> None:
    """Run v1 release-readiness checks without network access."""
    print_release_result(v1_readiness())


@app.command()
def serve(port: int = typer.Option(8765, "--port", min=1024, max=65535)) -> None:
    """Run the localhost-only Network Assistant API server."""
    import uvicorn

    uvicorn.run("app.server:api", host="127.0.0.1", port=port, reload=False)


@app.command()
def chat(server_url: str = typer.Option("http://127.0.0.1:8765", "--server-url")) -> None:
    """Open the Matrix-style local terminal chat console."""
    run_chat(server_url=server_url)


@agent_app.callback()
def agent(
    ctx: typer.Context,
    dry_policy: bool = typer.Option(False, "--dry-policy", help="Parse and evaluate policy without executing tools."),
    auto: bool = typer.Option(False, "--auto", help="Allow guided custom generated plan flows inside agent mode."),
) -> None:
    """Open the deterministic local network operations agent."""
    if ctx.invoked_subcommand is None:
        run_agent(dry_policy=dry_policy, auto=auto)


@agent_logs_app.callback()
def agent_logs(ctx: typer.Context, limit: int = typer.Option(25, "--limit", min=1, max=200)) -> None:
    """Show recent agent action logs."""
    if ctx.invoked_subcommand is None:
        print_agent_logs(list_agent_logs(limit=limit))


@agent_logs_app.command("show")
def agent_log_show(log_id: int) -> None:
    """Show a full agent action log entry."""
    print_agent_log_detail(get_agent_log(log_id))


@app.command()
def detect() -> None:
    """Detect the active local network."""
    try:
        print_network_info(detect_local_network())
    except NetworkDetectionError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@app.command()
def scan() -> None:
    """Safely scan the detected local private network and save results."""
    try:
        network_info = detect_local_network()
        validate_scan_target(network_info.cidr)
        scan_result = scan_network(network_info.cidr)
        save_scan_result(scan_result)
        print_scan_summary(scan_result)
    except (NetworkDetectionError, UnsafeNetworkError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@nmap_app.command("check")
def nmap_check() -> None:
    """Check whether the optional nmap system binary is available."""
    print_nmap_check()


@nmap_app.command("scan-local")
def nmap_scan_local(
    profile: str = typer.Option("common-ports", "--profile", help="Allowed: ping, common-ports, service-light."),
    yes: bool = typer.Option(False, "--yes", help="Skip interactive confirmation."),
) -> None:
    """Run a controlled nmap scan against the detected private local CIDR."""
    try:
        network_info = detect_local_network()
        target = validate_nmap_target(network_info.cidr)
        profile = validate_nmap_profile(profile)
        _confirm_nmap_scan(target, profile, yes)
        result = run_nmap_scan(target, profile)
        save_nmap_results(result)
        print_nmap_scan_result(result)
    except (NetworkDetectionError, UnsafeNetworkError, RuntimeError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@nmap_app.command("scan-host")
def nmap_scan_host(
    ip: str,
    profile: str = typer.Option("common-ports", "--profile", help="Allowed: ping, common-ports, service-light."),
    yes: bool = typer.Option(False, "--yes", help="Skip interactive confirmation."),
) -> None:
    """Run a controlled nmap scan against one private IP."""
    try:
        target = validate_nmap_target(ip)
        profile = validate_nmap_profile(profile)
        _confirm_nmap_scan(target, profile, yes)
        result = run_nmap_scan(target, profile)
        save_nmap_results(result)
        print_nmap_scan_result(result)
    except (UnsafeNetworkError, RuntimeError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@nmap_app.command("scan-device")
def nmap_scan_device(
    ip: str,
    profile: str = typer.Option("service-light", "--profile", help="Allowed: ping, common-ports, service-light."),
    yes: bool = typer.Option(False, "--yes", help="Skip interactive confirmation."),
) -> None:
    """Run a controlled nmap scan against a private IP already in inventory."""
    try:
        if get_device_profile(ip) is None:
            print_error("Device not found in local inventory.")
            raise typer.Exit(code=1)
        target = validate_nmap_target(ip)
        profile = validate_nmap_profile(profile)
        _confirm_nmap_scan(target, profile, yes)
        result = run_nmap_scan(target, profile)
        save_nmap_results(result)
        print_nmap_scan_result(result)
    except (UnsafeNetworkError, RuntimeError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


def _confirm_nmap_scan(target: str, profile: str, yes: bool) -> None:
    if yes:
        return
    if not typer.confirm(f"Run controlled nmap profile `{profile}` against {target}?", default=False):
        raise typer.Exit(code=1)


@app.command()
def devices() -> None:
    """List devices stored in the local SQLite inventory."""
    print_devices_table(list_devices())


@app.command()
def enrich() -> None:
    """Run passive enrichment against stored devices."""
    try:
        print_enrichment_summary(enrich_stored_devices())
    except NetworkDetectionError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@app.command()
def device(ip: str) -> None:
    """Show a full stored profile for one device."""
    print_device_profile(get_device_profile(ip))


@app.command("update-device")
def update_device(
    ip: str,
    vendor: str | None = typer.Option(None, "--vendor", help="Correct vendor name."),
    model: str | None = typer.Option(None, "--model", help="Correct model name."),
    device_type: str | None = typer.Option(None, "--type", help="Correct device type."),
) -> None:
    """Manually correct a stored device profile."""
    if not any([vendor, model, device_type]):
        print_error("Provide at least one of --vendor, --model, or --type.")
        raise typer.Exit(code=1)
    updated = update_device_profile(ip, vendor=vendor, model=model, device_type=device_type)
    if updated is None:
        print_error("Device not found in local inventory.")
        raise typer.Exit(code=1)
    print_device_profile(updated)


@app.command()
def report() -> None:
    """Print a terminal report from the latest scan."""
    print_latest_report(get_latest_scan_report())


@app.command()
def ask(
    question: str,
    show_context: bool = typer.Option(
        False,
        "--show-context",
        help="Print the exact redacted local context before calling DeepSeek.",
    ),
    no_llm: bool = typer.Option(
        False,
        "--no-llm",
        help="Print the redacted local context only; do not call DeepSeek.",
    ),
) -> None:
    """Ask DeepSeek to reason over stored local network data only."""
    try:
        validate_llm_question(question)
        if show_context or no_llm:
            context = build_local_network_context(question)
            print_llm_context(context)
        if no_llm:
            return
        answer = LLMPlanner().answer_question(question)
    except (LLMSafetyError, LLMPlannerError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
    print_llm_answer(question, answer)


@app.command("reset-db")
def reset_db() -> None:
    """Delete local scan data and recreate database tables."""
    confirmed = typer.confirm("Delete all local scan data and recreate the database?")
    if not confirmed:
        raise typer.Exit()
    reset_database()
    typer.echo("Database reset complete.")


@security_app.command("generate-key")
def security_generate_key() -> None:
    """Generate a Fernet key for CREDENTIAL_SECRET_KEY."""
    typer.echo(generate_credential_key())


@credentials_app.command("add")
def credentials_add(ip: str) -> None:
    """Add or replace encrypted SSH credentials for a stored device."""
    username = typer.prompt("Username")
    password = typer.prompt("Password", hide_input=True, confirmation_prompt=True)
    platform_hint = typer.prompt(
        "Platform hint (cisco_ios, mikrotik_routeros, linux, unknown_ssh)",
        default="unknown_ssh",
    )
    port = typer.prompt("SSH port", default=22, type=int)
    try:
        save_device_credential(
            ip_address=ip,
            username=username,
            password=password,
            platform_hint=platform_hint,
            port=port,
        )
    except (CredentialError, CredentialSecurityError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
    typer.echo("Credentials saved. Password was encrypted and was not printed.")


@credentials_app.command("list")
def credentials_list() -> None:
    """List stored credentials without exposing passwords."""
    print_credential_list(list_device_credentials())


@credentials_app.command("test")
def credentials_test(ip: str) -> None:
    """Test stored SSH credentials for a device."""
    try:
        print_connection_test(test_connection(ip))
    except (CredentialSecurityError, DeviceConnectionError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@credentials_app.command("delete")
def credentials_delete(ip: str) -> None:
    """Delete stored credentials for a device."""
    confirmed = typer.confirm(f"Delete stored credentials for {ip}?")
    if not confirmed:
        raise typer.Exit()
    deleted = delete_device_credential(ip)
    if not deleted:
        print_error("No stored credentials found for this device.")
        raise typer.Exit(code=1)
    typer.echo("Credentials deleted.")


@connect_app.command("test")
def connect_test(ip: str) -> None:
    """Test read-only SSH access for a stored device."""
    try:
        print_connection_test(test_connection(ip))
    except (CredentialSecurityError, DeviceConnectionError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@connect_app.command("collect")
def connect_collect(ip: str) -> None:
    """Run safe read-only profile collection for a stored device."""
    try:
        print_collection_result(run_readonly_profile_collection(ip))
    except (CredentialSecurityError, DeviceConnectionError, CommandPolicyError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@command_app.command("run")
def command_run(ip: str, command: str) -> None:
    """Run one allowlisted read-only command and store the output."""
    try:
        print_command_result(run_readonly_command(ip, command))
    except (CredentialSecurityError, DeviceConnectionError, CommandPolicyError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@command_app.command("history")
def command_history_cmd(ip: str, limit: int = typer.Option(25, "--limit", min=1, max=200)) -> None:
    """Show stored read-only command history for a device."""
    print_command_history(command_history(ip, limit=limit))


@diagnose_app.command("network")
def diagnose_network_cmd() -> None:
    """Run a guided diagnostic for the current local network."""
    try:
        print_diagnostic_result(diagnose_network())
    except (DiagnosticError, NetworkDetectionError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@diagnose_app.command("device")
def diagnose_device_cmd(ip: str) -> None:
    """Run a guided diagnostic for one stored device."""
    try:
        print_diagnostic_result(diagnose_device(ip))
    except DiagnosticError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@diagnose_app.command("management-ports")
def diagnose_management_ports_cmd() -> None:
    """Find devices with possible management or service ports."""
    print_diagnostic_result(diagnose_management_ports())


@diagnose_app.command("connectivity")
def diagnose_connectivity_cmd(target_ip: str) -> None:
    """Run safe local connectivity checks for a private target IP."""
    try:
        print_diagnostic_result(diagnose_connectivity(target_ip))
    except (DiagnosticError, NetworkDetectionError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@plan_app.command("vlan")
def plan_vlan(
    device: str = typer.Option(..., "--device", help="Inventory device IP."),
    vlan_id: int = typer.Option(..., "--vlan-id", help="VLAN ID, 1-4094."),
    name: str = typer.Option(..., "--name", help="VLAN name."),
    ports: str | None = typer.Option(None, "--ports", help="Optional Cisco interface range."),
) -> None:
    """Create a Cisco IOS VLAN change plan without executing it."""
    try:
        result = create_vlan_plan(device_ip=device, vlan_id=vlan_id, name=name, ports=ports)
    except ConfigPlanError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
    print_change_plan(result.plan)


@plan_app.command("mikrotik-address")
def plan_mikrotik_address(
    device: str = typer.Option(..., "--device", help="Inventory device IP."),
    interface: str = typer.Option(..., "--interface", help="RouterOS interface name."),
    address: str = typer.Option(..., "--address", help="IPv4 interface CIDR, such as 192.168.50.1/24."),
    comment: str | None = typer.Option(None, "--comment", help="Optional RouterOS comment."),
) -> None:
    """Create a MikroTik RouterOS IP address change plan without executing it."""
    try:
        result = create_mikrotik_address_plan(
            device_ip=device,
            interface=interface,
            address=address,
            comment=comment,
        )
    except ConfigPlanError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
    print_change_plan(result.plan)


@plan_app.command("mikrotik-dhcp")
def plan_mikrotik_dhcp(
    device: str = typer.Option(..., "--device", help="Inventory device IP."),
    name: str = typer.Option(..., "--name", help="RouterOS DHCP server name."),
    interface: str = typer.Option(..., "--interface", help="RouterOS interface name."),
    network: str = typer.Option(..., "--network", help="Private IPv4 DHCP network CIDR."),
    gateway: str = typer.Option(..., "--gateway", help="Gateway IPv4 address inside the DHCP network."),
    pool_name: str = typer.Option(..., "--pool-name", help="RouterOS IP pool name."),
    pool_range: str = typer.Option(..., "--pool-range", help="Pool range as start_ip-end_ip."),
    dns: str | None = typer.Option(None, "--dns", help="Optional comma-separated IPv4 DNS servers."),
    comment: str | None = typer.Option(None, "--comment", help="Optional RouterOS comment."),
) -> None:
    """Create a MikroTik RouterOS DHCP server plan without executing it."""
    try:
        result = create_mikrotik_dhcp_plan(
            device_ip=device,
            name=name,
            interface=interface,
            network=network,
            gateway=gateway,
            pool_name=pool_name,
            pool_range=pool_range,
            dns=dns,
            comment=comment,
        )
    except ConfigPlanError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
    print_change_plan(result.plan)


@plan_app.command("cisco-description")
def plan_cisco_description(
    device: str = typer.Option(..., "--device", help="Inventory device IP."),
    interface: str = typer.Option(..., "--interface", help="Single Cisco IOS interface, such as Gi0/5."),
    description: str = typer.Option(..., "--description", help="Interface description, max 80 characters."),
) -> None:
    """Create a Cisco IOS interface description plan without executing it."""
    try:
        result = create_cisco_description_plan(
            device_ip=device,
            interface=interface,
            description=description,
        )
    except ConfigPlanError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
    print_change_plan(result.plan)


@plan_app.command("cisco-access-port")
def plan_cisco_access_port(
    device: str = typer.Option(..., "--device", help="Inventory device IP."),
    interface: str = typer.Option(..., "--interface", help="Single Cisco IOS interface, such as Gi0/5."),
    vlan_id: int = typer.Option(..., "--vlan-id", help="Access VLAN ID, 1-4094."),
    description: str | None = typer.Option(None, "--description", help="Optional interface description, max 80 characters."),
) -> None:
    """Create a Cisco IOS access-port plan without executing it."""
    try:
        result = create_cisco_access_port_plan(
            device_ip=device,
            interface=interface,
            vlan_id=vlan_id,
            description=description,
        )
    except ConfigPlanError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
    print_change_plan(result.plan)


@plan_app.command("custom-generate")
def plan_custom_generate(
    goal: str = typer.Option(..., "--goal", help="Custom network task goal."),
    device: str | None = typer.Option(None, "--device", help="Inventory device IP."),
    platform: str | None = typer.Option(None, "--platform", help="mikrotik_routeros or cisco_ios."),
) -> None:
    """Ask DeepSeek for a custom Cisco/RouterOS command plan and save it as a draft."""
    try:
        draft = generate_custom_plan_from_goal(goal, target_device_ip=device, platform=platform)
        if draft.has_missing_inputs:
            print_error("DeepSeek needs more input before a plan can be saved: " + ", ".join(draft.missing_inputs))
            raise typer.Exit(code=1)
        plan = save_custom_plan(draft)
    except CustomPlanError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
    print_change_plan(plan)


@plan_app.command("list")
def plan_list() -> None:
    """List saved change plans."""
    print_change_plan_list(list_change_plans())


@plan_app.command("show")
def plan_show(plan_id: int) -> None:
    """Show one saved change plan."""
    plan = get_change_plan(plan_id)
    if plan is None:
        print_error(f"Change plan {plan_id} not found.")
        raise typer.Exit(code=1)
    print_change_plan(plan)


@plan_app.command("review")
def plan_review(plan_id: int) -> None:
    """Review a saved change plan and mark it reviewed."""
    try:
        plan = review_change_plan(plan_id)
    except ConfigPlanError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
    print_change_plan(plan)


@plan_app.command("approve")
def plan_approve(plan_id: int, note: str | None = typer.Option(None, "--note")) -> None:
    """Approve a reviewed/draft plan after explicit confirmation. No commands run."""
    plan = get_change_plan(plan_id)
    if plan is None:
        print_error(f"Change plan {plan_id} not found.")
        raise typer.Exit(code=1)
    warnings = approval_warnings(plan)
    for warning in warnings:
        print_error(warning)
    confirmed = typer.confirm("Approve this plan? APPROVAL ONLY -- NO COMMANDS EXECUTED")
    if not confirmed:
        raise typer.Exit()
    try:
        approved = approve_change_plan(plan_id, note=note)
    except ConfigPlanError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
    print_change_plan(approved)


@plan_app.command("reject")
def plan_reject(plan_id: int, note: str | None = typer.Option(None, "--note")) -> None:
    """Reject a saved change plan without deleting it."""
    try:
        plan = reject_change_plan(plan_id, note=note)
    except ConfigPlanError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
    print_change_plan(plan)


@plan_app.command("archive")
def plan_archive(plan_id: int, note: str | None = typer.Option(None, "--note")) -> None:
    """Archive a saved change plan."""
    try:
        plan = archive_change_plan(plan_id, note=note)
    except ConfigPlanError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
    print_change_plan(plan)


@plan_app.command("preflight")
def plan_preflight(plan_id: int, refresh: bool = typer.Option(False, "--refresh")) -> None:
    """Run preflight validation for an approved change plan. No config runs."""
    try:
        result = run_preflight(plan_id, refresh=refresh)
    except ConfigPlanError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
    print_preflight_result(result.plan, result.findings)


@plan_app.command("execute")
def plan_execute(plan_id: int, dry_run: bool = typer.Option(False, "--dry-run")) -> None:
    """Execute an approved, preflight-passed supported change plan."""
    confirmation = None
    double_confirmation = None
    if not dry_run:
        print_error("Configuration execution can change the target device.")
        plan = get_change_plan(plan_id)
        if plan and plan.plan_type in {"custom_routeros_plan", "custom_cisco_plan"}:
            if custom_plan_requires_double_confirmation(plan):
                double_confirmation = typer.prompt(f"Type {DOUBLE_CONFIRMATION_PHRASE} to continue")
            confirmation = typer.prompt(f"Type EXECUTE CUSTOM PLAN {plan_id} to continue")
        else:
            confirmation = typer.prompt(f"Type EXECUTE PLAN {plan_id} to continue")
    try:
        result = execute_change_plan(plan_id, dry_run=dry_run, confirmation=confirmation, double_confirmation=double_confirmation)
    except ConfigExecutionError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
    print_execution_result(result)


@plan_app.command("execution-history")
def plan_execution_history(plan_id: int) -> None:
    """Show execution logs for a change plan."""
    print_execution_history(get_execution_history(plan_id))


@plan_app.command("verify")
def plan_verify(plan_id: int) -> None:
    """Run read-only post-execution verification for a supported change plan."""
    try:
        result = verify_change_plan(plan_id)
    except ConfigExecutionError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
    print_execution_result(result)


@plan_app.command("save")
def plan_save(plan_id: int) -> None:
    """Persist an executed, verified Cisco IOS VLAN plan with write memory."""
    plan = get_change_plan(plan_id)
    if plan and plan.plan_type in {"mikrotik_address", "mikrotik_dhcp_server"}:
        print_error("MikroTik RouterOS applies changes immediately. There is no separate save step for this plan type.")
        raise typer.Exit(code=1)
    print_error("Saving configuration makes the executed change persistent.")
    confirmation = typer.prompt(f"Type SAVE CONFIG PLAN {plan_id} to continue")
    try:
        result = save_plan_config(plan_id, confirmation=confirmation)
    except ConfigExecutionError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
    print_execution_result(result)


@plan_app.command("rollback")
def plan_rollback(plan_id: int) -> None:
    """Apply strict rollback commands for an executed supported change plan."""
    print_error("Rollback changes the target device. It does not save configuration afterward.")
    confirmation = typer.prompt(f"Type ROLLBACK PLAN {plan_id} to continue")
    try:
        result = rollback_change_plan(plan_id, confirmation=confirmation)
    except ConfigExecutionError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
    print_execution_result(result)


@snapshot_app.command("list")
def snapshot_list(
    device: str | None = typer.Option(None, "--device"),
    plan_id: int | None = typer.Option(None, "--plan-id"),
) -> None:
    """List read-only config snapshots."""
    print_snapshot_list(list_snapshots(device_ip=device, plan_id=plan_id))


@snapshot_app.command("show")
def snapshot_show(snapshot_id: int, full: bool = typer.Option(False, "--full")) -> None:
    """Show a config snapshot preview or full content."""
    print_snapshot_detail(show_snapshot(snapshot_id), full=full)


@snapshot_app.command("capture")
def snapshot_capture(
    plan_id: int = typer.Option(..., "--plan-id"),
    snapshot_type: str = typer.Option("manual", "--type"),
) -> None:
    """Capture a manual read-only snapshot for a plan."""
    if snapshot_type != "manual":
        print_error("Manual CLI capture supports only --type manual.")
        raise typer.Exit(code=1)
    try:
        snapshot = capture_manual_snapshot(plan_id)
    except ConfigSnapshotError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
    print_snapshot_detail(snapshot, full=False)


@snapshot_app.command("export")
def snapshot_export(
    snapshot_id: int,
    export_format: str = typer.Option(..., "--format"),
    output: str = typer.Option(..., "--output"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    """Export a config snapshot to txt, json, or Markdown."""
    try:
        result = write_snapshot_export_file(
            snapshot_id=snapshot_id,
            export_format=export_format,
            output_path=output,
            force=force,
        )
    except ConfigSnapshotError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
    print_snapshot_export_result(result)


@snapshot_app.command("restore-guidance")
def snapshot_restore_guidance(snapshot_id: int) -> None:
    """Show deterministic manual restore guidance for a snapshot."""
    try:
        guidance = generate_restore_guidance(snapshot_id)
    except ConfigSnapshotError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
    print_snapshot_restore_guidance(guidance)


@lab_app.command("checklist")
def lab_checklist_command() -> None:
    """Show the safe lab validation checklist."""
    print_lab_checklist(lab_checklist())


@lab_app.command("validate-device")
def lab_validate_device(ip_address: str) -> None:
    """Inspect stored readiness evidence for a lab device without SSH."""
    print_lab_validation_result(validate_lab_device(ip_address))


@lab_app.command("validate-plan")
def lab_validate_plan(plan_id: int) -> None:
    """Check whether a plan is lab-ready without executing it."""
    print_lab_validation_result(validate_lab_plan(plan_id))


@lab_app.command("integration-check")
def lab_integration_check(connect: bool = typer.Option(False, "--connect")) -> None:
    """Check optional real-device integration test readiness."""
    print_lab_integration_result(integration_check(connect=connect))


@lab_app.command("integration-report")
def lab_integration_report() -> None:
    """Show stored integration-related records without network actions."""
    print_lab_integration_result(integration_report())


@topology_app.command("build")
def topology_build() -> None:
    """Build and save a read-only topology snapshot from stored evidence."""
    print_topology_build_result(build_topology_snapshot())


@topology_app.command("show")
def topology_show(snapshot_id: int | None = typer.Argument(None)) -> None:
    """Show the latest topology snapshot, or a specific snapshot id."""
    if snapshot_id is None:
        print_topology_snapshot(get_latest_topology())
    else:
        print_topology_snapshot(get_topology(snapshot_id))


@topology_app.command("export")
def topology_export(
    export_format: str = typer.Option("json", "--format", help="Export format: json or mermaid"),
    snapshot_id: int | None = typer.Option(None, "--snapshot-id"),
) -> None:
    """Export topology as JSON or Mermaid text."""
    normalized = export_format.lower().strip()
    if normalized == "json":
        import json

        print_topology_export(json.dumps(export_topology_json(snapshot_id), indent=2, default=str), "json")
        return
    if normalized == "mermaid":
        print_topology_export(export_topology_mermaid(snapshot_id), "mermaid")
        return
    print_error("Unsupported topology export format. Use `json` or `mermaid`.")
    raise typer.Exit(code=1)


@topology_app.command("export-file")
def topology_export_file(
    export_format: str = typer.Option(..., "--format", help="mermaid, json, or html."),
    output: str = typer.Option(..., "--output", help="Output file path."),
    snapshot_id: int | None = typer.Option(None, "--snapshot-id", help="Optional topology snapshot id."),
    offline: bool = typer.Option(False, "--offline", help="For HTML, omit external Mermaid CDN script."),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing output file."),
) -> None:
    """Write a topology snapshot export to a shareable file."""
    try:
        print_topology_file_export(
            write_topology_export_file(
                export_format=export_format,
                output_path=output,
                snapshot_id=snapshot_id,
                offline=offline,
                force=force,
            )
        )
    except (TopologyExportError, ValueError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@topology_app.command("report")
def topology_report(
    output: str = typer.Option(..., "--output", help="Markdown report output path."),
    snapshot_id: int | None = typer.Option(None, "--snapshot-id", help="Optional topology snapshot id."),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing output file."),
) -> None:
    """Write a deterministic Markdown topology report."""
    try:
        print_topology_file_export(write_topology_report_file(output_path=output, snapshot_id=snapshot_id, force=force))
    except (TopologyExportError, ValueError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@topology_app.command("explain")
def topology_explain(snapshot_id: int | None = typer.Option(None, "--snapshot-id")) -> None:
    """Explain topology confidence and missing evidence without DeepSeek."""
    print_topology_explanation(explain_topology(snapshot_id))


@topology_app.command("risk-check")
def topology_risk_check(plan_id: int = typer.Option(..., "--plan-id", help="Change plan id.")) -> None:
    """Inspect topology-aware warnings for a saved plan. No network commands run."""
    plan = get_change_plan(plan_id)
    if plan is None:
        print_error(f"Change plan {plan_id} not found.")
        raise typer.Exit(code=1)
    print_topology_risk_findings(plan_id, analyze_plan_topology_risk(plan))


@topology_app.command("rebuild-with-manual")
def topology_rebuild_with_manual() -> None:
    """Build a topology snapshot and overlay manual nodes, edges, and notes."""
    print_topology_build_result(rebuild_topology_with_manual())


@manual_node_app.command("add")
def manual_node_add(
    key: str = typer.Option(..., "--key", help="Stable manual node key."),
    label: str = typer.Option(..., "--label", help="Display label."),
    node_type: str = typer.Option(..., "--type", help="Node type."),
    ip_address: str | None = typer.Option(None, "--ip", help="Optional IP address."),
    mac_address: str | None = typer.Option(None, "--mac", help="Optional MAC address."),
    vendor: str | None = typer.Option(None, "--vendor", help="Optional vendor."),
    notes: str | None = typer.Option(None, "--notes", help="Optional notes."),
) -> None:
    """Add a manual topology node to the local database only."""
    try:
        print_manual_topology_operation_result(
            add_manual_node(
                node_key=key,
                label=label,
                node_type=node_type,
                ip_address=ip_address,
                mac_address=mac_address,
                vendor=vendor,
                notes=notes,
            )
        )
    except ManualTopologyError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@manual_node_app.command("list")
def manual_node_list() -> None:
    """List manual topology nodes."""
    print_manual_topology_nodes(list_manual_nodes())


@manual_node_app.command("delete")
def manual_node_delete(node_id: int) -> None:
    """Delete a manual topology node after confirmation."""
    if not typer.confirm(f"Delete manual topology node {node_id}?"):
        print_error("Delete cancelled.")
        raise typer.Exit(code=1)
    try:
        print_manual_topology_operation_result(delete_manual_node(node_id, confirm=True))
    except ManualTopologyError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@manual_edge_app.command("add")
def manual_edge_add(
    source: str = typer.Option(..., "--source", help="Source node key."),
    target: str = typer.Option(..., "--target", help="Target node key."),
    relation: str = typer.Option("manual", "--relation", help="Relation type."),
    label: str | None = typer.Option(None, "--label", help="Optional edge label."),
    confidence: str = typer.Option("high", "--confidence", help="low, medium, or high."),
    notes: str | None = typer.Option(None, "--notes", help="Optional notes."),
) -> None:
    """Add a manual topology edge to the local database only."""
    try:
        print_manual_topology_operation_result(
            add_manual_edge(
                source_node_key=source,
                target_node_key=target,
                relation_type=relation,
                label=label,
                confidence=confidence,
                notes=notes,
            )
        )
    except ManualTopologyError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@manual_edge_app.command("list")
def manual_edge_list() -> None:
    """List manual topology edges."""
    print_manual_topology_edges(list_manual_edges())


@manual_edge_app.command("delete")
def manual_edge_delete(edge_id: int) -> None:
    """Delete a manual topology edge after confirmation."""
    if not typer.confirm(f"Delete manual topology edge {edge_id}?"):
        print_error("Delete cancelled.")
        raise typer.Exit(code=1)
    try:
        print_manual_topology_operation_result(delete_manual_edge(edge_id, confirm=True))
    except ManualTopologyError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@manual_note_app.command("add")
def manual_note_add(
    target_type: str = typer.Option(..., "--target-type", help="node, edge, or topology."),
    target_key: str | None = typer.Option(None, "--target-key", help="Node key or edge key like source->target."),
    note: str = typer.Option(..., "--note", help="Manual note text."),
) -> None:
    """Add a manual topology note to the local database only."""
    try:
        print_manual_topology_operation_result(add_manual_note(target_type=target_type, target_key=target_key, note=note))
    except ManualTopologyError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@manual_note_app.command("list")
def manual_note_list() -> None:
    """List manual topology notes."""
    print_manual_topology_notes(list_manual_notes())


@manual_note_app.command("delete")
def manual_note_delete(note_id: int) -> None:
    """Delete a manual topology note after confirmation."""
    if not typer.confirm(f"Delete manual topology note {note_id}?"):
        print_error("Delete cancelled.")
        raise typer.Exit(code=1)
    try:
        print_manual_topology_operation_result(delete_manual_note(note_id, confirm=True))
    except ManualTopologyError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@knowledge_app.command("add")
def knowledge_add(
    title: str | None = typer.Option(None, "--title"),
    vendor: str | None = typer.Option(None, "--vendor"),
    model: str | None = typer.Option(None, "--model"),
    device_type: str | None = typer.Option(None, "--type"),
    doc_type: str = typer.Option("vendor_note", "--doc-type"),
    tags: str = typer.Option("", "--tags"),
    source_name: str | None = typer.Option(None, "--source-name"),
    trusted: bool = typer.Option(False, "--trusted"),
    source_type: str = typer.Option("manual", "--source-type"),
    source_url: str | None = typer.Option(None, "--source-url"),
) -> None:
    """Manually add reusable local device knowledge."""
    title = title or typer.prompt("Title")
    if not vendor:
        vendor = typer.prompt("Vendor", default="")
    if model is None:
        model = typer.prompt("Model", default="")
    if device_type is None:
        device_type = typer.prompt("Device type", default="")
    if doc_type not in SUPPORTED_DOC_TYPES:
        doc_type = typer.prompt("Doc type", default="vendor_note")
    if not tags:
        tags = typer.prompt("Tags comma-separated", default="")
    if source_name is None:
        source_name = typer.prompt("Source name", default="")
    trusted = typer.confirm("Mark this knowledge as trusted?", default=trusted)
    content = _prompt_multiline("Content")
    try:
        item = add_knowledge(
            title=title,
            content=content,
            vendor=vendor,
            model=model,
            device_type=device_type,
            doc_type=doc_type,
            tags=tags,
            source_name=source_name,
            is_trusted=trusted,
            source_type=source_type,
            source_url=source_url,
        )
    except KnowledgeError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
    print_knowledge_added(item)


@knowledge_app.command("import-file")
def knowledge_import_file(
    path: str,
    vendor: str | None = typer.Option(None, "--vendor"),
    model: str | None = typer.Option(None, "--model"),
    doc_type: str = typer.Option("vendor_note", "--doc-type"),
    tags: str = typer.Option("", "--tags"),
    title: str | None = typer.Option(None, "--title"),
    source_name: str | None = typer.Option(None, "--source-name"),
    trusted: bool = typer.Option(False, "--trusted"),
) -> None:
    """Import a .txt or .md file into local knowledge."""
    try:
        item = import_knowledge_file(
            path=path,
            vendor=vendor,
            model=model,
            doc_type=doc_type,
            tags=tags,
            title=title,
            source_name=source_name,
            is_trusted=trusted,
        )
    except KnowledgeError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
    print_knowledge_added(item)


@knowledge_app.command("list")
def knowledge_list() -> None:
    """List local knowledge documents."""
    print_knowledge_list(list_knowledge())


@knowledge_app.command("show")
def knowledge_show(knowledge_id: int) -> None:
    """Show one local knowledge document."""
    item = get_knowledge(knowledge_id)
    if item is None:
        print_error(f"Knowledge document {knowledge_id} not found.")
        raise typer.Exit(code=1)
    print_knowledge_document(item)


@knowledge_app.command("search")
def knowledge_search(terms: list[str] = typer.Argument(...)) -> None:
    """Search local knowledge with SQLite FTS when available."""
    print_knowledge_search_results(search_knowledge(" ".join(terms)))


@knowledge_app.command("delete")
def knowledge_delete(knowledge_id: int) -> None:
    """Delete a local knowledge document after confirmation."""
    confirmed = typer.confirm(f"Delete knowledge document {knowledge_id}?")
    if not confirmed:
        raise typer.Exit()
    if not delete_knowledge(knowledge_id):
        print_error(f"Knowledge document {knowledge_id} not found.")
        raise typer.Exit(code=1)
    typer.echo("Knowledge document deleted.")


@knowledge_app.command("fetch-url")
def knowledge_fetch_url(
    url: str,
    vendor: str = typer.Option(..., "--vendor"),
    model: str | None = typer.Option(None, "--model"),
    doc_type: str = typer.Option("vendor_note", "--doc-type"),
    tags: str = typer.Option("", "--tags"),
    trusted: bool = typer.Option(False, "--trusted"),
) -> None:
    """Fetch an explicit public documentation URL into local knowledge."""
    try:
        result = save_fetched_document_as_knowledge(
            url=url,
            vendor=vendor,
            model=model,
            doc_type=doc_type,
            trusted=trusted,
            tags=tags,
        )
    except DocFetchError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
    print_fetched_document_saved(result)


@knowledge_app.command("fetch-docs")
def knowledge_fetch_docs(
    vendor: str = typer.Option(..., "--vendor"),
    model: str = typer.Option(..., "--model"),
) -> None:
    """Search official docs when configured; otherwise direct users to fetch-url."""
    try:
        results = search_official_docs(vendor, model)
    except DocFetchError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
    if not results:
        print_error(
            "Automatic doc search is not configured yet. Use `python main.py knowledge fetch-url "
            "<official-url> --vendor <vendor> --model <model>`."
        )
        raise typer.Exit(code=1)
    for index, result in enumerate(results, start=1):
        typer.echo(f"{index}. {result.title} - {result.url}")


def _prompt_multiline(label: str) -> str:
    typer.echo(f"{label}. Enter text below. Finish with a line containing only a single dot.")
    lines: list[str] = []
    while True:
        line = typer.prompt("", prompt_suffix="")
        if line == ".":
            break
        lines.append(line)
    return "\n".join(lines)
