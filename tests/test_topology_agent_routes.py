from app.agent.intent_parser import parse_intent
from app.agent.policy import evaluate_agent_action
from app.services.command_router import route_local_command


def test_agent_routes_topology_commands():
    for text, tool in (
        ("build topology", "build_topology"),
        ("show topology", "show_topology"),
        ("export topology mermaid", "export_topology_mermaid"),
        ("explain topology", "explain_topology"),
    ):
        intent = parse_intent(text)
        decision = evaluate_agent_action(intent.tool_name, intent.args)
        assert intent.tool_name == tool
        assert decision.allowed
        assert decision.risk_level == "low"


def test_chat_routes_show_topology_without_execution():
    result = route_local_command("show topology")

    assert result.kind == "topology"
