from types import SimpleNamespace

from app.agent.agent_models import AgentResult, SkillPlan
from app.agent.agent_loop import process_agent_input
from app.agent.result_renderer import print_result
from app.agent.session_memory import SessionMemory


def _fake_execute(intent, _memory, decision=None):
    risk = decision.risk_level if decision else "low"
    return AgentResult(intent.tool_name, risk, True, "ok", data={"echo_args": intent.args})


def test_scan_my_network_routes_through_skill_planner(monkeypatch):
    import app.agent.agent_loop as agent_loop

    monkeypatch.setattr(agent_loop, "log_agent_action", lambda **_kwargs: None)
    monkeypatch.setattr(agent_loop.settings, "llm_enabled", True)
    monkeypatch.setattr(
        agent_loop,
        "select_skill_plan",
        lambda **_kwargs: SkillPlan(
            selected_skill="network_scanning",
            selected_tool="scan_network",
            reason="best match",
            risk_level="medium",
            confidence=0.9,
        ),
    )
    monkeypatch.setattr(agent_loop, "execute_agent_intent", _fake_execute)

    result = process_agent_input("scan my network", SessionMemory(), session_id="skill-flow-1", confirm_fn=lambda *_args: True)

    assert result.action == "scan_network"
    assert result.data["_planner"]["selected_skill"] == "network_scanning"


def test_gateway_question_routes_to_answer_network_fact(monkeypatch):
    import app.agent.agent_loop as agent_loop

    monkeypatch.setattr(agent_loop, "log_agent_action", lambda **_kwargs: None)
    monkeypatch.setattr(agent_loop.settings, "llm_enabled", True)
    monkeypatch.setattr(
        agent_loop,
        "select_skill_plan",
        lambda **_kwargs: SkillPlan(
            selected_skill="network_scanning",
            selected_tool="answer_network_fact",
            reason="gateway fact request",
            risk_level="low",
            confidence=0.92,
        ),
    )
    monkeypatch.setattr(
        agent_loop,
        "execute_agent_intent",
        lambda intent, _memory, decision=None: AgentResult(
            intent.tool_name,
            decision.risk_level if decision else "low",
            True,
            "Gateway 192.168.88.1: MikroTik, router.",
            data={"gateway_ip": "192.168.88.1"},
        ),
    )

    result = process_agent_input("what is my gateway", SessionMemory(), session_id="skill-flow-2")

    assert result.action == "answer_network_fact"
    assert result.data["_planner"]["selected_skill"] in {"network_scanning", "router_connection"}


def test_connect_to_router_routes_to_router_workflow(monkeypatch):
    import app.agent.agent_loop as agent_loop

    monkeypatch.setattr(agent_loop, "log_agent_action", lambda **_kwargs: None)
    monkeypatch.setattr(agent_loop.settings, "llm_enabled", True)
    monkeypatch.setattr(
        agent_loop,
        "select_skill_plan",
        lambda **_kwargs: SkillPlan(
            selected_skill="router_connection",
            selected_tool="router_connect_workflow",
            reason="router intent",
            risk_level="medium",
            confidence=0.95,
        ),
    )
    monkeypatch.setattr(agent_loop, "execute_agent_intent", _fake_execute)

    result = process_agent_input("connect to my router", SessionMemory(), session_id="skill-flow-3", confirm_fn=lambda *_args: True)

    assert result.action == "router_connect_workflow"
    assert result.data["_planner"]["selected_skill"] == "router_connection"


def test_topology_report_routes_to_topology_workflow(monkeypatch):
    import app.agent.agent_loop as agent_loop

    monkeypatch.setattr(agent_loop, "log_agent_action", lambda **_kwargs: None)
    monkeypatch.setattr(agent_loop.settings, "llm_enabled", True)
    monkeypatch.setattr(
        agent_loop,
        "select_skill_plan",
        lambda **_kwargs: SkillPlan(
            selected_skill="topology",
            selected_tool="workflow_topology_report",
            reason="topology report request",
            risk_level="low",
            confidence=0.9,
        ),
    )
    monkeypatch.setattr(agent_loop, "execute_agent_intent", _fake_execute)

    result = process_agent_input("make topology report", SessionMemory(), session_id="skill-flow-4")

    assert result.action in {"workflow_topology_report", "topology_report_file"}
    assert result.data["_planner"]["selected_skill"] == "topology"


def test_cisco_vlan_request_creates_plan_not_execution(monkeypatch):
    import app.agent.agent_loop as agent_loop

    monkeypatch.setattr(agent_loop, "log_agent_action", lambda **_kwargs: None)
    monkeypatch.setattr(agent_loop.settings, "llm_enabled", True)
    monkeypatch.setattr(
        agent_loop,
        "select_skill_plan",
        lambda **_kwargs: SkillPlan(
            selected_skill="cisco_operations",
            selected_tool="create_vlan_plan",
            reason="specific cisco vlan task",
            risk_level="medium",
            confidence=0.91,
        ),
    )
    monkeypatch.setattr(agent_loop, "execute_agent_intent", _fake_execute)

    result = process_agent_input("create a VLAN on Cisco switch", SessionMemory(), session_id="skill-flow-5", confirm_fn=lambda *_args: True)

    assert result.action == "create_vlan_plan"
    assert result.action != "execute_plan"


def test_plugin_generation_not_selected_when_existing_skill_fits(monkeypatch):
    import app.agent.agent_loop as agent_loop

    monkeypatch.setattr(agent_loop, "log_agent_action", lambda **_kwargs: None)
    monkeypatch.setattr(agent_loop.settings, "llm_enabled", True)
    monkeypatch.setattr(
        agent_loop,
        "select_skill_plan",
        lambda **_kwargs: SkillPlan(
            selected_skill="network_scanning",
            selected_tool="scan_network",
            reason="existing skill can satisfy scan",
            risk_level="medium",
            confidence=0.93,
        ),
    )
    monkeypatch.setattr(agent_loop, "execute_agent_intent", _fake_execute)

    result = process_agent_input("generate plugin to scan router", SessionMemory(), session_id="skill-flow-6", confirm_fn=lambda *_args: True)

    assert result.action != "generate_plugin_tool"
    assert result.action == "scan_network"


def test_public_ip_scan_blocked_before_skill_planning(monkeypatch):
    import app.agent.agent_loop as agent_loop

    monkeypatch.setattr(agent_loop, "log_agent_action", lambda **_kwargs: None)
    monkeypatch.setattr(agent_loop.settings, "llm_enabled", True)
    monkeypatch.setattr(
        agent_loop,
        "select_skill_plan",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("planner should not run for blocked input")),
    )

    result = process_agent_input("nmap 8.8.8.8 -A", SessionMemory(), session_id="skill-flow-7")

    assert result.action == "blocked_request"
    assert result.ok is False


def test_raw_ssh_blocked_before_skill_planning(monkeypatch):
    import app.agent.agent_loop as agent_loop

    monkeypatch.setattr(agent_loop, "log_agent_action", lambda **_kwargs: None)
    monkeypatch.setattr(agent_loop.settings, "llm_enabled", True)
    monkeypatch.setattr(
        agent_loop,
        "select_skill_plan",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("planner should not run for blocked input")),
    )

    result = process_agent_input("ssh admin@192.168.88.1", SessionMemory(), session_id="skill-flow-8")

    assert result.action == "blocked_request"
    assert result.ok is False


def test_when_llm_disabled_deterministic_fallback_still_works(monkeypatch):
    import app.agent.agent_loop as agent_loop

    monkeypatch.setattr(agent_loop, "log_agent_action", lambda **_kwargs: None)
    monkeypatch.setattr(agent_loop.settings, "llm_enabled", False)
    monkeypatch.setattr(agent_loop, "detect_local_network", lambda: SimpleNamespace(cidr="192.168.88.0/24"))
    monkeypatch.setattr(agent_loop, "scan_network", lambda _cidr: SimpleNamespace(live_hosts_count=1))
    monkeypatch.setattr(agent_loop, "save_scan_result", lambda _scan: None)
    monkeypatch.setattr(agent_loop, "list_devices", lambda: [])

    result = process_agent_input("scan my network", SessionMemory(), session_id="skill-flow-9", confirm_fn=lambda *_args: True)

    assert result.action == "scan_network"


def test_normal_renderer_output_does_not_show_raw_json(monkeypatch, capsys):
    from app.agent import result_renderer

    monkeypatch.setattr(result_renderer, "console", result_renderer.Console(force_terminal=False, width=140))
    result_renderer.set_trace(False)
    result = AgentResult(
        action="scan_network",
        risk_level="medium",
        ok=True,
        message="done",
        data={"network": "192.168.88.0/24", "live_hosts": 1, "devices": []},
    )

    print_result(result)
    output = capsys.readouterr().out

    assert "Raw tool details" not in output
