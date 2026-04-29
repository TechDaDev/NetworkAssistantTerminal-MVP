from app.agent.agent_loop import process_agent_input
from app.agent.session_memory import SessionMemory


def test_unknown_intent_fallback_returns_examples(monkeypatch):
    monkeypatch.setattr("app.agent.agent_loop.log_agent_action", lambda **_kwargs: None)

    result = process_agent_input("do some network magic", SessionMemory(), session_id="test-session")

    assert result.action == "unknown"
    assert not result.ok
    assert "I did not understand" in result.message
    assert "workflow scan and diagnose" in result.message
    assert "prepare mikrotik dhcp" in result.message


def test_agent_help_includes_workflows_and_high_risk_warning(monkeypatch):
    monkeypatch.setattr("app.agent.agent_loop.log_agent_action", lambda **_kwargs: None)

    result = process_agent_input("help", SessionMemory(), session_id="test-session")

    assert result.ok
    assert "Workflows" in result.data["commands"]
    blocked = result.data["commands"]["Blocked high-risk actions"]
    assert any("Execution/save/rollback require direct CLI exact confirmation" in item for item in blocked)
