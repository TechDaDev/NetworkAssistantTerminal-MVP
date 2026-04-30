from app.agent.tool_retriever import retrieve_relevant_tools


def test_connect_router_retrieves_router_tools():
    names = [tool.tool_name for tool in retrieve_relevant_tools("connect to my router")]

    assert "router_connect_workflow" in names
    assert "plugin_generate" not in names[:3]


def test_scan_network_retrieves_scan_and_devices():
    names = [tool.tool_name for tool in retrieve_relevant_tools("scan my network")]

    assert names[0] == "scan_network"
    assert "show_devices" in names


def test_config_task_prefers_custom_plan_not_plugin():
    names = [tool.tool_name for tool in retrieve_relevant_tools("configure MikroTik load balancing")]

    assert "custom_plan_generate" in names[:3]
    assert "plugin_generate" not in names[:3]


def test_explicit_plugin_request_allows_plugin_generation():
    names = [tool.tool_name for tool in retrieve_relevant_tools("create a reusable tool for MikroTik PCC load balancing")]

    assert "plugin_generate" in names[:3]
