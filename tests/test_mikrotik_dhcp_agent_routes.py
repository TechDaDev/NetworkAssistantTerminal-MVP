from app.agent.intent_parser import parse_intent
from app.agent.policy import evaluate_agent_action


def test_agent_parses_mikrotik_dhcp_plan():
    intent = parse_intent(
        "create mikrotik dhcp plan device=192.168.88.1 name=lab-dhcp interface=bridge "
        "network=192.168.50.0/24 gateway=192.168.50.1 pool-name=lab-pool "
        "pool-range=192.168.50.100-192.168.50.200 dns=8.8.8.8,1.1.1.1 comment=LAB"
    )

    assert intent.tool_name == "create_mikrotik_dhcp_plan"
    assert intent.args["device"] == "192.168.88.1"
    assert intent.args["name"] == "lab-dhcp"
    assert intent.args["pool_name"] == "lab-pool"
    assert intent.args["pool_range"] == "192.168.50.100-192.168.50.200"


def test_mikrotik_dhcp_plan_creation_is_medium_risk():
    decision = evaluate_agent_action("create_mikrotik_dhcp_plan", {})

    assert decision.allowed
    assert decision.risk_level == "medium"
    assert decision.requires_confirmation
