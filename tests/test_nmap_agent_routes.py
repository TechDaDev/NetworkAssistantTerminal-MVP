from app.agent.intent_parser import parse_intent
from app.agent.policy import evaluate_agent_action


def test_agent_nmap_check_is_low_risk():
    intent = parse_intent("nmap check")
    decision = evaluate_agent_action(intent.tool_name, intent.args)

    assert intent.tool_name == "nmap_check"
    assert decision.allowed is True
    assert decision.risk_level == "low"


def test_agent_nmap_scan_is_medium_risk_and_requires_confirmation():
    intent = parse_intent("nmap scan local service light")
    decision = evaluate_agent_action(intent.tool_name, intent.args)

    assert intent.tool_name == "nmap_scan_local"
    assert intent.args["profile"] == "service-light"
    assert decision.allowed is True
    assert decision.risk_level == "medium"
    assert decision.requires_confirmation is True


def test_agent_parses_nmap_host_scan():
    intent = parse_intent("nmap scan 192.168.88.1")

    assert intent.tool_name == "nmap_scan_host"
    assert intent.args["target"] == "192.168.88.1"
    assert intent.args["profile"] == "common-ports"


def test_agent_blocks_public_nmap_target():
    intent = parse_intent("nmap scan 8.8.8.8")
    decision = evaluate_agent_action(intent.tool_name, intent.args)

    assert decision.allowed is False
    assert "Public" in decision.message or "public" in decision.message


def test_agent_blocks_raw_nmap_flags():
    intent = parse_intent("nmap -A 192.168.88.1")
    decision = evaluate_agent_action(intent.tool_name, intent.args)

    assert intent.tool_name == "blocked_request"
    assert decision.allowed is False


def test_agent_blocks_nmap_scripts():
    intent = parse_intent("nmap --script vuln 192.168.88.1")
    decision = evaluate_agent_action(intent.tool_name, intent.args)

    assert intent.tool_name == "blocked_request"
    assert decision.allowed is False
