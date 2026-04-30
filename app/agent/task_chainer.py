from __future__ import annotations


def get_followup_tools(tool_name: str, user_request: str) -> list[str]:
    lowered = user_request.lower()
    if tool_name == "scan_network":
        followups = ["show_devices"]
        if any(term in lowered for term in ("tell me", "summary", "summarize", "what is connected", "diagnose")):
            followups.append("diagnose_network")
        return followups
    if tool_name in {"nmap_scan_local", "nmap_scan_host", "nmap_scan_device"}:
        return ["show_report"]
    if tool_name == "build_topology":
        return ["topology_report" if "report" in lowered else "show_topology"]
    if tool_name in {
        "create_cisco_vlan_plan",
        "create_cisco_description_plan",
        "create_cisco_access_port_plan",
        "create_mikrotik_address_plan",
        "create_mikrotik_dhcp_plan",
        "custom_plan_generate",
    }:
        return ["custom_plan_show"]
    return []


def should_auto_run_followup(primary_tool: str, followup_tool: str, user_request: str) -> bool:
    if followup_tool in {"execute_plan", "save_plan", "rollback_plan"}:
        return False
    return followup_tool in get_followup_tools(primary_tool, user_request)


def build_task_chain(user_request: str, selected_tool: str) -> list[str]:
    chain = [selected_tool]
    chain.extend(get_followup_tools(selected_tool, user_request))
    return chain
