from types import SimpleNamespace

from app.agent.agent_loop import process_agent_input
from app.agent.intent_parser import parse_intent
from app.agent.policy import evaluate_agent_action
from app.agent.result_renderer import set_trace
from app.agent.session_memory import SessionMemory


def test_gateway_vendor_question_maps_to_answer_network_fact():
    intent = parse_intent("what is the vendor of the network gateway?")

    assert intent.tool_name == "answer_network_fact"


def test_answer_network_fact_is_allowed_without_confirmation():
    decision = evaluate_agent_action("answer_network_fact", {})

    assert decision.allowed is True
    assert decision.risk_level == "low"
    assert decision.requires_confirmation is False


def test_gateway_question_executes_answer_network_fact_without_plugin(monkeypatch):
    import app.agent.agent_loop as agent_loop

    monkeypatch.setattr(agent_loop, "log_agent_action", lambda **_kwargs: None)
    monkeypatch.setattr(
        agent_loop,
        "_offer_plugin_generation",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("plugin fallback should not be used")),
    )
    monkeypatch.setattr(
        agent_loop,
        "answer_network_fact",
        lambda _q: SimpleNamespace(
            gateway_ip="192.168.88.1",
            vendor="MikroTik",
            device_type="router",
            in_inventory=True,
            as_dict=lambda: {"gateway_ip": "192.168.88.1", "vendor": "MikroTik", "device_type": "router"},
        ),
    )

    result = process_agent_input(
        "what is the vendor of the network gateway?",
        SessionMemory(),
        session_id="network-fact-test",
    )

    assert result.action == "answer_network_fact"
    assert result.ok is True
    assert "Gateway 192.168.88.1" in result.message


def test_unknown_network_request_hides_retrieved_tools_by_default(monkeypatch):
    import app.agent.agent_loop as agent_loop

    monkeypatch.setattr(agent_loop, "log_agent_action", lambda **_kwargs: None)
    monkeypatch.setattr(
        agent_loop,
        "retrieve_relevant_tools",
        lambda *_args, **_kwargs: [SimpleNamespace(tool_name="plugin_generate")],
    )
    monkeypatch.setattr(
        agent_loop,
        "retrieve_relevant_skills",
        lambda *_args, **_kwargs: [SimpleNamespace(metadata=SimpleNamespace(skill_name="plugin_factory"))],
    )
    set_trace(False)

    result = process_agent_input("do some network magic", SessionMemory(), session_id="unknown-default-test")

    assert result.action == "unknown"
    assert result.ok is False
    assert result.data is None


def test_trace_mode_includes_retrieved_tools_and_skills(monkeypatch):
    import app.agent.agent_loop as agent_loop

    monkeypatch.setattr(agent_loop, "log_agent_action", lambda **_kwargs: None)
    monkeypatch.setattr(
        agent_loop,
        "retrieve_relevant_tools",
        lambda *_args, **_kwargs: [SimpleNamespace(tool_name="plugin_generate")],
    )
    monkeypatch.setattr(
        agent_loop,
        "retrieve_relevant_skills",
        lambda *_args, **_kwargs: [SimpleNamespace(metadata=SimpleNamespace(skill_name="plugin_factory"))],
    )

    set_trace(True)
    try:
        result = process_agent_input("do some network magic", SessionMemory(), session_id="unknown-trace-test")
    finally:
        set_trace(False)

    assert result.action == "unknown"
    assert result.ok is False
    assert result.data is not None
    assert result.data["relevant_tools"] == ["plugin_generate"]
    assert result.data["relevant_skills"] == ["plugin_factory"]
