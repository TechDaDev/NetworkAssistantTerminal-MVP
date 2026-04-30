from types import SimpleNamespace

from app.agent.agent_loop import process_agent_input
from app.agent.session_memory import SessionMemory


def test_connect_router_uses_router_workflow_not_plugin(monkeypatch):
    import app.agent.agent_loop as agent_loop

    monkeypatch.setattr(agent_loop, "log_agent_action", lambda **_kwargs: None)
    monkeypatch.setattr(agent_loop, "detect_local_network", lambda: SimpleNamespace(gateway_ip="192.168.88.1", cidr="192.168.88.0/24"))
    monkeypatch.setattr(
        agent_loop,
        "get_device_profile",
        lambda ip: SimpleNamespace(ip_address=ip, vendor_guess="MikroTik", device_type_guess="router"),
    )
    monkeypatch.setattr(agent_loop, "get_credential_for_ip", lambda _ip: None)
    called = {"plugin": False}
    monkeypatch.setattr(agent_loop, "_execute_plugin_generation_flow", lambda *_args, **_kwargs: called.__setitem__("plugin", True))

    result = process_agent_input("connect to my router", SessionMemory(), session_id="router-test", confirm_fn=lambda *_args: True)

    assert result.action == "router_connect_workflow"
    assert result.ok is True
    assert result.next_command == "nat credentials add 192.168.88.1"
    assert called["plugin"] is False
