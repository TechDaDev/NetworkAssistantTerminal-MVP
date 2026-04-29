from app.agent.intent_parser import parse_intent
from app.agent.policy import evaluate_agent_action


def test_agent_parses_cisco_description_plan():
    intent = parse_intent("plan cisco description device=192.168.88.20 interface=Gi0/5 description=LAB-PC-01")

    assert intent.tool_name == "create_cisco_description_plan"
    assert intent.args["device"] == "192.168.88.20"
    assert intent.args["interface"] == "Gi0/5"
    assert intent.args["description"] == "LAB-PC-01"


def test_agent_parses_cisco_access_port_plan():
    intent = parse_intent("create cisco access port plan device=192.168.88.20 interface=Gi0/5 vlan=30 description=LAB-PC-01")

    assert intent.tool_name == "create_cisco_access_port_plan"
    assert intent.args["vlan"] == 30


def test_cisco_interface_plan_creation_is_medium_risk():
    decision = evaluate_agent_action("create_cisco_access_port_plan", {})

    assert decision.allowed
    assert decision.risk_level == "medium"
    assert decision.requires_confirmation
