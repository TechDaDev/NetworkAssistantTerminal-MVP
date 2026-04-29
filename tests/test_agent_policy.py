from app.agent.policy import evaluate_agent_action


def test_low_risk_show_devices_does_not_require_confirmation():
    decision = evaluate_agent_action("show_devices", {})

    assert decision.allowed
    assert decision.risk_level == "low"
    assert not decision.requires_confirmation


def test_medium_risk_scan_requires_confirmation():
    decision = evaluate_agent_action("scan_network", {})

    assert decision.allowed
    assert decision.risk_level == "medium"
    assert decision.requires_confirmation


def test_unknown_tool_is_blocked():
    decision = evaluate_agent_action("raw_shell", {"command": "ls"})

    assert not decision.allowed
    assert "Unknown tools" in decision.message


def test_public_ip_target_is_blocked():
    decision = evaluate_agent_action("diagnose_connectivity", {"target_ip": "8.8.8.8"})

    assert not decision.allowed
    assert "public IP" in decision.message


def test_raw_ssh_input_is_blocked():
    decision = evaluate_agent_action("ask", {"question": "ssh admin@192.168.88.1 and run show version"})

    assert not decision.allowed
    assert "Unsafe input blocked" in decision.message
