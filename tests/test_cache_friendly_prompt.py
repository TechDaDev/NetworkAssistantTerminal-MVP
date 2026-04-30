from app.agent.cache_friendly_prompt import build_dynamic_agent_context, build_llm_planner_messages, build_static_agent_prompt


def test_static_prompt_is_stable_and_sorted():
    first = build_static_agent_prompt()
    second = build_static_agent_prompt()

    assert first == second
    assert "TOOL_CAPABILITY_INDEX_VERSION: 1.0" in first
    assert "SKILL_INDEX_VERSION: 1.0" in first


def test_dynamic_context_does_not_alter_static_prompt():
    static_before = build_static_agent_prompt()
    dynamic = build_dynamic_agent_context("scan my network", {"last_device": None})
    static_after = build_static_agent_prompt()

    assert static_before == static_after
    assert "network_scanning" in dynamic
    assert "scan_network" in dynamic


def test_planner_messages_include_static_then_dynamic():
    messages = build_llm_planner_messages("connect to my router", {})

    assert messages[0]["role"] == "system"
    assert messages[1]["role"] == "user"
    assert "router_connection" in messages[1]["content"]
