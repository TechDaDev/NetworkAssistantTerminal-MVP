from types import SimpleNamespace

from app.agent.agent_loop import process_agent_input
from app.agent.intent_parser import parse_intent
from app.agent.session_memory import SessionMemory


def test_scan_network_chains_to_devices(monkeypatch):
    import app.agent.agent_loop as agent_loop

    monkeypatch.setattr(agent_loop, "log_agent_action", lambda **_kwargs: None)
    monkeypatch.setattr(agent_loop, "detect_local_network", lambda: SimpleNamespace(cidr="192.168.88.0/24"))
    monkeypatch.setattr(agent_loop, "scan_network", lambda _cidr: SimpleNamespace(live_hosts_count=2))
    monkeypatch.setattr(agent_loop, "save_scan_result", lambda _scan: None)
    monkeypatch.setattr(
        agent_loop,
        "list_devices",
        lambda: [
            SimpleNamespace(ip_address="192.168.88.1", vendor_guess="MikroTik", device_type_guess="router", ports=[]),
            SimpleNamespace(ip_address="192.168.88.20", vendor_guess="Cisco", device_type_guess="switch", ports=[]),
        ],
    )

    result = process_agent_input("scan my network", SessionMemory(), session_id="scan-test", confirm_fn=lambda *_args: True)

    assert result.action == "scan_network"
    assert result.ok is True
    assert "Inventory now has 2 device" in result.message
    assert result.data["task_chain"] == ["scan_network", "show_devices"]


def test_scan_network_summary_chains_to_diagnose(monkeypatch):
    import app.agent.agent_loop as agent_loop

    monkeypatch.setattr(agent_loop, "log_agent_action", lambda **_kwargs: None)
    monkeypatch.setattr(agent_loop, "detect_local_network", lambda: SimpleNamespace(cidr="192.168.88.0/24"))
    monkeypatch.setattr(agent_loop, "scan_network", lambda _cidr: SimpleNamespace(live_hosts_count=1))
    monkeypatch.setattr(agent_loop, "save_scan_result", lambda _scan: None)
    monkeypatch.setattr(agent_loop, "list_devices", lambda: [])
    monkeypatch.setattr(agent_loop, "diagnose_network", lambda: SimpleNamespace(summary="Network looks usable."))

    result = process_agent_input("scan my network and summarize", SessionMemory(), session_id="scan-summary-test", confirm_fn=lambda *_args: True)

    assert result.data["task_chain"] == ["scan_network", "show_devices", "diagnose_network"]
    assert "Network looks usable" in result.message


def test_non_network_request_rejected_before_llm(monkeypatch):
    import app.agent.agent_loop as agent_loop

    monkeypatch.setattr(agent_loop, "log_agent_action", lambda **_kwargs: None)
    monkeypatch.setattr(agent_loop.LLMPlanner, "answer_question", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("LLM called")))

    result = process_agent_input("write me a love poem", SessionMemory(), session_id="domain-test")

    assert result.action == "blocked_request"
    assert result.ok is False
    assert "local network operations" in result.message


def test_what_tools_and_skills_have_deterministic_intents():
    assert parse_intent("what tools do you have?").tool_name == "list_tools"
    assert parse_intent("what skills do you have?").tool_name == "list_skills"


def test_connect_router_does_not_parse_as_plugin():
    assert parse_intent("connect to my router").tool_name == "router_connect_workflow"


def test_config_mikrotik_prefers_custom_plan():
    assert parse_intent("configure MikroTik load balancing").tool_name == "custom_plan_goal"


def test_explicit_plugin_request_parses_plugin():
    assert parse_intent("create a reusable tool for MikroTik PCC load balancing").tool_name == "generate_plugin_tool"
