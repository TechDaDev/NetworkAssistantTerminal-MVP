from app.agent.domain_guard import decide_network_domain, is_plugin_worthy_request


def test_network_request_allowed():
    decision = decide_network_domain("connect to my router")

    assert decision.is_network_related is True


def test_non_network_request_rejected():
    decision = decide_network_domain("write me a love poem")

    assert decision.is_network_related is False
    assert "local network operations" in decision.reason


def test_plugin_worthy_detection():
    assert is_plugin_worthy_request("create a reusable tool for MikroTik PCC")
    assert not is_plugin_worthy_request("connect to my router")
