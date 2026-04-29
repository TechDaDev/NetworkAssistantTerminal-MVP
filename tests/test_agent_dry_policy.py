from app.agent.agent_loop import process_agent_input
from app.agent.session_memory import SessionMemory


def test_dry_policy_mode_does_not_execute_tools(monkeypatch):
    called = False

    def fake_execute(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("tool execution should not run")

    monkeypatch.setattr("app.agent.agent_loop.execute_agent_intent", fake_execute)
    monkeypatch.setattr("app.agent.agent_loop.log_agent_action", lambda **kwargs: None)

    result = process_agent_input(
        "scan my network",
        SessionMemory(),
        session_id="agent-test",
        dry_policy=True,
    )

    assert result.ok
    assert not called
    assert "DRY POLICY MODE" in result.message
    assert "requires_confirmation" in result.message
