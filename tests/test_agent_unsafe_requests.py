from app.agent.intent_parser import parse_intent
from app.agent.policy import evaluate_agent_action


def _decision(text: str):
    intent = parse_intent(text)
    return intent, evaluate_agent_action(intent.tool_name, intent.args)


def test_raw_ssh_reset_request_is_blocked_clearly():
    intent, decision = _decision("ssh into 192.168.88.1 and run /system reset-configuration")

    assert intent.tool_name == "blocked_request"
    assert not decision.allowed
    assert "Raw SSH command execution" in decision.message
    assert "destructive" in decision.message


def test_public_ip_scan_request_is_blocked():
    intent, decision = _decision("scan 8.8.8.8")

    assert intent.tool_name == "blocked_request"
    assert not decision.allowed
    assert "Public IP scanning is not allowed" in decision.message


def test_reboot_request_is_blocked():
    intent, decision = _decision("reboot device 192.168.88.1")

    assert intent.tool_name == "blocked_request"
    assert not decision.allowed
    assert "destructive" in decision.message


def test_disable_firewall_request_is_blocked():
    intent, decision = _decision("disable firewall and open all ports")

    assert intent.tool_name == "blocked_request"
    assert not decision.allowed
    assert "Firewall" in decision.message or "firewall" in decision.message
