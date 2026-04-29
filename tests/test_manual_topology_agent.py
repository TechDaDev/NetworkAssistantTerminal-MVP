from app.agent.intent_parser import parse_intent
from app.agent.policy import evaluate_agent_action


def test_agent_parses_manual_topology_node_add():
    intent = parse_intent("add manual topology node key=core-switch label='Core Switch' type=switch ip=192.168.88.2")

    assert intent.tool_name == "add_manual_topology_node"
    assert intent.args["key"] == "core-switch"
    assert intent.args["label"] == "Core Switch"
    assert intent.args["type"] == "switch"


def test_agent_parses_manual_topology_edge_add():
    intent = parse_intent("add manual topology edge source=gateway target=core-switch relation=manual label='uplink ether2'")

    assert intent.tool_name == "add_manual_topology_edge"
    assert intent.args["source"] == "gateway"
    assert intent.args["target"] == "core-switch"
    assert intent.args["label"] == "uplink ether2"


def test_agent_blocks_manual_topology_delete():
    intent = parse_intent("delete manual topology node 1")
    decision = evaluate_agent_action(intent.tool_name, intent.args)

    assert intent.tool_name == "delete_manual_topology"
    assert not decision.allowed
    assert decision.direct_cli_required
