from __future__ import annotations

from functools import lru_cache

from pydantic import BaseModel, Field


TOOL_CAPABILITY_INDEX_VERSION = "1.0"


class ToolCapability(BaseModel):
    tool_name: str
    display_name: str
    description: str
    category: str
    risk_level: str
    enabled: bool = True
    user_phrases: list[str] = Field(default_factory=list)
    required_inputs: list[str] = Field(default_factory=list)
    optional_inputs: list[str] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    outputs: list[str] = Field(default_factory=list)
    forbidden_uses: list[str] = Field(default_factory=list)
    examples: list[str] = Field(default_factory=list)
    related_tools: list[str] = Field(default_factory=list)
    followup_tools: list[str] = Field(default_factory=list)
    related_skills: list[str] = Field(default_factory=list)


def cap(
    tool_name: str,
    display_name: str,
    description: str,
    category: str,
    risk_level: str,
    *,
    user_phrases: list[str] | None = None,
    required_inputs: list[str] | None = None,
    optional_inputs: list[str] | None = None,
    preconditions: list[str] | None = None,
    outputs: list[str] | None = None,
    forbidden_uses: list[str] | None = None,
    examples: list[str] | None = None,
    related_tools: list[str] | None = None,
    followup_tools: list[str] | None = None,
    related_skills: list[str] | None = None,
) -> ToolCapability:
    return ToolCapability(
        tool_name=tool_name,
        display_name=display_name,
        description=description,
        category=category,
        risk_level=risk_level,
        user_phrases=user_phrases or [],
        required_inputs=required_inputs or [],
        optional_inputs=optional_inputs or [],
        preconditions=preconditions or [],
        outputs=outputs or [],
        forbidden_uses=forbidden_uses or [],
        examples=examples or [],
        related_tools=related_tools or [],
        followup_tools=followup_tools or [],
        related_skills=related_skills or [],
    )


@lru_cache(maxsize=1)
def load_tool_capabilities() -> tuple[ToolCapability, ...]:
    items = [
        cap("show_devices", "Show Devices", "List stored inventory devices.", "inventory", "low", user_phrases=["show devices", "list devices", "what devices"], outputs=["device table"], related_skills=["network_scanning"]),
        cap("show_device", "Show Device", "Show one stored device profile.", "inventory", "low", user_phrases=["show device", "inspect device"], required_inputs=["ip"], outputs=["device profile"], related_skills=["router_connection"]),
        cap("show_report", "Show Latest Report", "Show latest scan report.", "inventory", "low", user_phrases=["latest report", "show report"], outputs=["scan summary"], related_skills=["network_scanning"]),
        cap("detect_network", "Detect Network", "Detect interface, local CIDR, gateway, and MAC.", "inventory", "low", user_phrases=["detect network", "find gateway"], outputs=["local network facts"], related_skills=["router_connection", "network_scanning"]),
        cap(
            "answer_network_fact",
            "Answer Local Network Fact",
            "Answer questions about the local gateway, network CIDR, interface, and vendor using network detection and inventory. No LLM required.",
            "diagnostics",
            "low",
            user_phrases=[
                "what is my gateway",
                "what is the gateway ip",
                "what is the network gateway",
                "what is the gateway",
                "what is the vendor of the gateway",
                "what is the vendor of the network gateway",
                "what type is the gateway",
                "is the gateway in inventory",
                "what ports are open on the gateway",
                "what subnet am i connected to",
                "what network am i connected to",
                "what is my local ip",
                "what is my network interface",
                "gateway info",
                "gateway information",
            ],
            required_inputs=[],
            outputs=["gateway IP", "local IP", "interface", "network CIDR", "gateway vendor/type if inventory has it", "gateway ports if inventory has them"],
            forbidden_uses=["plugin generation", "custom plans", "SSH", "LLM vendor guessing"],
            followup_tools=["scan_network", "enrich_devices", "nmap_scan_host", "router_connect_workflow"],
            related_skills=["router_connection", "diagnostics", "network_scanning"],
        ),
        cap("scan_network", "Scan Network", "Run safe built-in local private network discovery.", "scan", "medium", user_phrases=["scan my network", "find devices", "discover devices", "what is connected to my network", "show open ports", "check services"], preconditions=["private local CIDR", "CIDR /24 or smaller"], outputs=["saved inventory", "common ports"], forbidden_uses=["public scans", "large CIDRs"], followup_tools=["show_devices", "diagnose_network"], related_skills=["network_scanning"]),
        cap("enrich_devices", "Enrich Devices", "Passively enrich stored devices with banners and titles.", "scan", "medium", user_phrases=["enrich devices"], preconditions=["stored inventory"], outputs=["enriched inventory"], followup_tools=["show_devices"], related_skills=["network_scanning"]),
        cap("nmap_check", "Nmap Check", "Check optional system nmap availability.", "nmap", "low", user_phrases=["nmap check"], outputs=["availability"], related_skills=["nmap_scanning"]),
        cap("nmap_scan_local", "Nmap Scan Local", "Run controlled nmap safe profile against local private CIDR.", "nmap", "medium", user_phrases=["nmap scan local", "deeper service scan"], optional_inputs=["profile"], preconditions=["nmap installed", "private /24 or smaller"], forbidden_uses=["raw flags", "public targets", "vuln scripts"], followup_tools=["show_report"], related_skills=["nmap_scanning"]),
        cap("nmap_scan_host", "Nmap Scan Host", "Run controlled nmap safe profile against one private host.", "nmap", "medium", user_phrases=["nmap scan 192.168.88.1"], required_inputs=["target"], optional_inputs=["profile"], forbidden_uses=["public targets", "raw flags"], followup_tools=["show_report"], related_skills=["nmap_scanning"]),
        cap("nmap_scan_device", "Nmap Scan Device", "Run controlled nmap safe profile against an inventory device.", "nmap", "medium", user_phrases=["nmap scan device"], required_inputs=["target"], optional_inputs=["profile"], preconditions=["device exists"], followup_tools=["show_report"], related_skills=["nmap_scanning"]),
        cap("credentials_add_guidance", "Credentials Add Guidance", "Tell user how to add encrypted SSH credentials.", "ssh_readonly", "low", user_phrases=["add credentials"], required_inputs=["ip"], outputs=["CLI guidance"], related_skills=["router_connection", "ssh_readonly_collection"]),
        cap("credentials_test", "Credentials Test", "Test saved SSH credentials.", "ssh_readonly", "medium", user_phrases=["test credentials"], required_inputs=["ip"], preconditions=["credentials exist"], outputs=["login result"], related_skills=["ssh_readonly_collection"]),
        cap("connect_test", "Connect Test", "Test read-only SSH access.", "ssh_readonly", "medium", user_phrases=["connect test", "test ssh"], required_inputs=["ip"], preconditions=["credentials exist"], outputs=["connection result"], forbidden_uses=["raw SSH commands"], related_skills=["ssh_readonly_collection"]),
        cap("connect_collect_readonly", "Read-Only Collection", "Run allowlisted read-only profile collection over SSH.", "ssh_readonly", "medium", user_phrases=["collect router info", "read router configuration"], required_inputs=["ip"], preconditions=["credentials exist"], outputs=["command history"], forbidden_uses=["configuration commands", "raw SSH"], related_skills=["router_connection", "ssh_readonly_collection"]),
        cap("router_connect_workflow", "Router Connect Workflow", "Detect gateway, check inventory and credentials, then offer read-only collection.", "ssh_readonly", "medium", user_phrases=["connect to my router", "connect to router", "connect to gateway", "login to router", "inspect my router", "inspect router", "inspect gateway", "check my router", "check router", "collect router info", "collect gateway info", "read router configuration", "show router information"], outputs=["gateway summary", "credential guidance", "optional read-only collection"], forbidden_uses=["plugin generation", "configuration commands"], related_tools=["detect_network", "show_device", "scan_network", "credentials_test", "connect_collect_readonly"], related_skills=["router_connection"]),
        cap("diagnose_network", "Diagnose Network", "Diagnose local network state from stored data.", "diagnostics", "low", user_phrases=["diagnose network", "summarize network"], outputs=["diagnostic findings"], related_skills=["diagnostics"]),
        cap("diagnose_device", "Diagnose Device", "Diagnose one known device.", "diagnostics", "low", user_phrases=["diagnose device", "inspect device"], required_inputs=["ip"], outputs=["device findings"], related_skills=["diagnostics"]),
        cap("diagnose_management_ports", "Diagnose Management Ports", "Summarize risky management/service ports.", "diagnostics", "low", user_phrases=["show risky management ports"], outputs=["port findings"], related_skills=["diagnostics"]),
        cap("diagnose_connectivity", "Diagnose Connectivity", "Run safe private-IP connectivity check.", "diagnostics", "low", user_phrases=["ping check", "diagnose connectivity"], required_inputs=["target_ip"], forbidden_uses=["public targets"], related_skills=["diagnostics"]),
        cap("build_topology", "Build Topology", "Build read-only topology snapshot from local evidence.", "topology", "low", user_phrases=["build topology"], outputs=["topology snapshot"], followup_tools=["show_topology"], related_skills=["topology"]),
        cap("show_topology", "Show Topology", "Show latest topology snapshot.", "topology", "low", user_phrases=["show topology"], outputs=["topology summary"], related_skills=["topology"]),
        cap("explain_topology", "Explain Topology", "Explain topology evidence and confidence.", "topology", "low", user_phrases=["explain topology"], outputs=["topology explanation"], related_skills=["topology"]),
        cap("export_topology", "Export Topology", "Export topology as JSON, Mermaid, HTML, or report file.", "topology", "low", user_phrases=["export topology"], optional_inputs=["format", "output"], outputs=["exported topology"], related_skills=["topology"]),
        cap("topology_report", "Topology Report", "Write a topology report.", "topology", "low", user_phrases=["topology report"], optional_inputs=["output"], outputs=["Markdown report"], related_skills=["topology"]),
        cap("topology_risk_check", "Topology Risk Check", "Inspect topology-aware plan warnings.", "topology", "low", user_phrases=["topology risk check"], required_inputs=["plan_id"], related_skills=["topology"]),
        cap("manual_topology_node", "Manual Topology Node", "Add/list manual topology nodes.", "topology", "low", user_phrases=["manual topology node"], related_skills=["topology"]),
        cap("manual_topology_edge", "Manual Topology Edge", "Add/list manual topology edges.", "topology", "low", user_phrases=["manual topology edge"], related_skills=["topology"]),
        cap("manual_topology_note", "Manual Topology Note", "Add/list manual topology notes.", "topology", "low", user_phrases=["manual topology note"], related_skills=["topology"]),
        cap("knowledge_search", "Knowledge Search", "Search local knowledge/RAG documents.", "knowledge", "low", user_phrases=["knowledge search"], required_inputs=["query"], related_skills=["knowledge_rag"]),
        cap("knowledge_list", "Knowledge List", "List local knowledge documents.", "knowledge", "low", user_phrases=["knowledge list"], related_skills=["knowledge_rag"]),
        cap("knowledge_show", "Knowledge Show", "Show one knowledge document.", "knowledge", "low", user_phrases=["show knowledge"], required_inputs=["knowledge_id"], related_skills=["knowledge_rag"]),
        cap("knowledge_add_guidance", "Knowledge Add Guidance", "Guide adding local knowledge.", "knowledge", "low", user_phrases=["add knowledge"], related_skills=["knowledge_rag"]),
        cap("knowledge_fetch_url", "Knowledge Fetch URL", "Explicitly fetch public docs into local knowledge.", "knowledge", "medium", user_phrases=["fetch docs"], required_inputs=["url", "vendor"], forbidden_uses=["automatic browsing"], related_skills=["knowledge_rag"]),
        cap("snapshot_list", "Snapshot List", "List configuration snapshots.", "snapshot", "low", user_phrases=["list snapshots"], related_skills=["snapshots_backup"]),
        cap("snapshot_show", "Snapshot Show", "Show one configuration snapshot.", "snapshot", "low", user_phrases=["show snapshot"], required_inputs=["snapshot_id"], related_skills=["snapshots_backup"]),
        cap("snapshot_capture", "Snapshot Capture", "Capture read-only snapshot for a plan.", "snapshot", "medium", user_phrases=["backup router", "backup config", "capture snapshot"], required_inputs=["plan_id"], preconditions=["credentials exist"], forbidden_uses=["restore automation"], related_skills=["snapshots_backup"]),
        cap("snapshot_export", "Snapshot Export", "Export a snapshot to a local file.", "snapshot", "low", user_phrases=["export snapshot"], required_inputs=["snapshot_id", "format", "output"], related_skills=["snapshots_backup"]),
        cap("snapshot_restore_guidance", "Snapshot Restore Guidance", "Show deterministic restore guidance without executing restore.", "snapshot", "low", user_phrases=["restore guidance"], required_inputs=["snapshot_id"], forbidden_uses=["automatic restore"], related_skills=["snapshots_backup"]),
        cap("create_cisco_vlan_plan", "Create Cisco VLAN Plan", "Create fixed Cisco VLAN plan.", "planning", "medium", user_phrases=["add vlan"], required_inputs=["device", "vlan", "name"], followup_tools=["custom_plan_show"], related_skills=["cisco_operations"]),
        cap("create_cisco_description_plan", "Create Cisco Description Plan", "Create fixed Cisco interface description plan.", "planning", "medium", user_phrases=["interface description"], required_inputs=["device", "interface", "description"], followup_tools=["custom_plan_show"], related_skills=["cisco_operations"]),
        cap("create_cisco_access_port_plan", "Create Cisco Access-Port Plan", "Create fixed Cisco access-port plan.", "planning", "medium", user_phrases=["configure access port"], required_inputs=["device", "interface", "vlan"], followup_tools=["custom_plan_show"], related_skills=["cisco_operations"]),
        cap("create_mikrotik_address_plan", "Create MikroTik Address Plan", "Create fixed MikroTik IP address plan.", "planning", "medium", user_phrases=["mikrotik address"], required_inputs=["device", "interface", "address"], followup_tools=["custom_plan_show"], related_skills=["mikrotik_operations"]),
        cap("create_mikrotik_dhcp_plan", "Create MikroTik DHCP Plan", "Create fixed MikroTik DHCP plan.", "planning", "medium", user_phrases=["configure dhcp"], required_inputs=["device", "name", "interface", "network", "gateway", "pool"], followup_tools=["custom_plan_show"], related_skills=["mikrotik_operations"]),
        cap("custom_plan_generate", "Custom Plan Generate", "Generate governed Cisco/RouterOS command ChangePlan for advanced config tasks.", "custom_plan", "high", user_phrases=["configure mikrotik load balancing", "setup failover", "add static route", "add nat rule", "add firewall rule", "configure router", "configure switch"], optional_inputs=["device", "platform"], preconditions=["network task", "human approval"], forbidden_uses=["direct execution", "security abuse"], related_skills=["custom_plans", "cisco_operations", "mikrotik_operations"]),
        cap("custom_plan_show", "Plan Show", "Show saved ChangePlan.", "planning", "low", user_phrases=["show plan"], required_inputs=["plan_id"], related_skills=["custom_plans"]),
        cap("custom_plan_review", "Plan Review", "Mark ChangePlan reviewed.", "planning", "medium", user_phrases=["review plan"], required_inputs=["plan_id"], related_skills=["custom_plans"]),
        cap("custom_plan_approve", "Plan Approve", "Approve ChangePlan with confirmation.", "planning", "medium", user_phrases=["approve plan"], required_inputs=["plan_id"], related_skills=["custom_plans"]),
        cap("custom_plan_preflight", "Plan Preflight", "Run ChangePlan preflight.", "planning", "low", user_phrases=["preflight plan"], required_inputs=["plan_id"], related_skills=["custom_plans"]),
        cap("execute_plan", "Execute Plan", "Execute approved/preflight-passed plan with exact confirmation.", "execution", "high", user_phrases=["execute plan"], required_inputs=["plan_id"], preconditions=["approved", "preflight passed", "backup"], forbidden_uses=["auto execution"], related_skills=["safety_policy"]),
        cap("save_plan", "Save Plan", "Save Cisco running config after verified execution.", "execution", "high", user_phrases=["save plan"], required_inputs=["plan_id"], forbidden_uses=["automatic save"], related_skills=["cisco_operations"]),
        cap("rollback_plan", "Rollback Plan", "Rollback a plan with exact confirmation.", "rollback", "high", user_phrases=["rollback plan"], required_inputs=["plan_id"], forbidden_uses=["automatic rollback except failed verification"], related_skills=["safety_policy"]),
        cap("verify_plan", "Verify Plan", "Run read-only verification for a plan.", "execution", "low", user_phrases=["verify plan"], required_inputs=["plan_id"], related_skills=["custom_plans"]),
        cap("plugin_generate", "Plugin Generate", "Generate a reusable pure local plugin for planner/parser/validator/reporter/diagnostic tasks.", "plugin", "medium", user_phrases=["create a reusable tool", "make a parser", "build a planner plugin", "add a new tool"], preconditions=["network-related", "no existing tool", "not enough for custom plan"], forbidden_uses=["normal operational tasks", "SSH", "subprocess", "sockets"], related_skills=["plugin_factory"]),
        cap("plugin_list", "Plugin List", "List plugin tools.", "plugin", "low", user_phrases=["plugin list"], related_skills=["plugin_factory"]),
        cap("plugin_show", "Plugin Show", "Show plugin detail and validation report.", "plugin", "low", user_phrases=["plugin show"], required_inputs=["tool_name"], related_skills=["plugin_factory"]),
        cap("plugin_validate", "Plugin Validate", "Validate pending or approved plugin.", "plugin", "low", user_phrases=["plugin validate"], required_inputs=["tool_name"], related_skills=["plugin_factory"]),
        cap("plugin_approve", "Plugin Approve", "Approve validation-passed plugin.", "plugin", "medium", user_phrases=["plugin approve"], required_inputs=["tool_name"], related_skills=["plugin_factory"]),
        cap("plugin_disable", "Plugin Disable", "Disable approved plugin.", "plugin", "medium", user_phrases=["plugin disable"], required_inputs=["tool_name"], related_skills=["plugin_factory"]),
        cap("plugin_run", "Plugin Run", "Run approved plugin.", "plugin", "medium", user_phrases=["plugin run"], required_inputs=["tool_name"], optional_inputs=["input_json"], preconditions=["approved plugin"], related_skills=["plugin_factory"]),
        cap("lab_checklist", "Lab Checklist", "Show lab validation checklist.", "lab", "low", user_phrases=["lab checklist"], related_skills=["lab_release"]),
        cap("lab_validate_device", "Lab Validate Device", "Validate lab device readiness from stored data.", "lab", "low", user_phrases=["lab validate device"], required_inputs=["ip"], related_skills=["lab_release"]),
        cap("lab_validate_plan", "Lab Validate Plan", "Validate lab plan readiness.", "lab", "low", user_phrases=["lab validate plan"], required_inputs=["plan_id"], related_skills=["lab_release"]),
        cap("lab_integration_check", "Lab Integration Check", "Check skipped-by-default lab integration setup.", "lab", "low", user_phrases=["integration check"], related_skills=["lab_release"]),
        cap("doctor", "Doctor", "Run local doctor checks.", "release", "low", user_phrases=["doctor"], related_skills=["lab_release", "troubleshooting"]),
        cap("release_readiness", "Release Readiness", "Run release readiness checks.", "release", "low", user_phrases=["release readiness"], related_skills=["lab_release"]),
        cap("config_show", "Config Show", "Show safe config with secrets redacted.", "config", "low", user_phrases=["config show"], related_skills=["lab_release"]),
        cap("version", "Version", "Show CLI version.", "release", "low", user_phrases=["version"], related_skills=["lab_release"]),
    ]
    return tuple(sorted(items, key=lambda item: item.tool_name))


def list_tool_capabilities() -> list[ToolCapability]:
    return list(load_tool_capabilities())


def get_tool_capability(tool_name: str) -> ToolCapability | None:
    return next((item for item in load_tool_capabilities() if item.tool_name == tool_name), None)
