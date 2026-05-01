from app.agent.tool_capability_index import get_tool_capability, list_tool_capabilities


def test_capability_index_loads():
    tools = list_tool_capabilities()

    assert tools
    assert tools == sorted(tools, key=lambda item: item.tool_name)


def test_required_tools_exist_in_index():
    required = {
        "show_devices",
        "show_device",
        "show_report",
        "detect_network",
        "answer_network_fact",
        "scan_network",
        "enrich_devices",
        "nmap_check",
        "nmap_scan_local",
        "nmap_scan_host",
        "nmap_scan_device",
        "connect_collect_readonly",
        "router_connect_workflow",
        "diagnose_network",
        "build_topology",
        "knowledge_search",
        "snapshot_capture",
        "custom_plan_generate",
        "execute_plan",
        "plugin_generate",
        "doctor",
        "release_readiness",
        "version",
    }

    missing = [name for name in required if get_tool_capability(name) is None]

    assert missing == []
