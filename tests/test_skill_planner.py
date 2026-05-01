from app.agent.skill_retriever import retrieve_relevant_skills
from app.agent.tool_retriever import retrieve_relevant_tools
from app.services.skill_planner import normalize_tool_name, select_skill_plan


def test_skill_planner_fallback_picks_scan_skill_and_tool(monkeypatch):
    from app import config

    monkeypatch.setattr(config.settings, "llm_enabled", False)
    skills = retrieve_relevant_skills("scan my network", limit=6)
    tools = retrieve_relevant_tools("scan my network", limit=8)

    plan = select_skill_plan("scan my network", {}, skills, tools)

    assert plan.selected_skill == "network_scanning"
    assert plan.selected_tool == "scan_network"


def test_skill_planner_fallback_picks_router_connection_workflow(monkeypatch):
    from app import config

    monkeypatch.setattr(config.settings, "llm_enabled", False)
    skills = retrieve_relevant_skills("connect to my router", limit=6)
    tools = retrieve_relevant_tools("connect to my router", limit=8)

    plan = select_skill_plan("connect to my router", {}, skills, tools)

    assert plan.selected_skill == "router_connection"
    assert plan.selected_tool == "router_connect_workflow"


def test_tool_alias_normalization_maps_capability_names_to_registry_names():
    assert normalize_tool_name("show_report") == "latest_report"
    assert normalize_tool_name("custom_plan_generate") == "custom_plan_goal"
    assert normalize_tool_name("plugin_generate") == "generate_plugin_tool"
