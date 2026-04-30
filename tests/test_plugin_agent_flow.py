from types import SimpleNamespace

from app.agent import agent_loop
from app.agent.agent_loop import process_agent_input
from app.agent.session_memory import SessionMemory


class Draft:
    tool_name = "safe_reporter"


def test_agent_offers_plugin_generation_for_network_reusable_tool(monkeypatch):
    monkeypatch.setattr(agent_loop, "log_agent_action", lambda **_kwargs: None)
    monkeypatch.setattr(agent_loop.Confirm, "ask", lambda *args, **kwargs: False)
    monkeypatch.setattr(agent_loop, "_execute_plugin_generation_flow", lambda goal, risk: SimpleNamespace(action="generate_plugin_tool", risk_level=risk, ok=False, message="declined", next_command=None, data=None, policy_decision=""))

    result = process_agent_input("create a reusable tool for parsing router interface notes", SessionMemory(), session_id="agent-test", confirm_fn=lambda *_args: True)

    assert result.action == "generate_plugin_tool"
    assert result.ok is False


def test_agent_does_not_run_generated_plugin_without_approval(monkeypatch):
    plugin = SimpleNamespace(tool_name="safe_reporter", validation_status="passed", validation_report="ok")
    ran = {"called": False}
    monkeypatch.setattr(agent_loop, "log_agent_action", lambda **_kwargs: None)
    monkeypatch.setattr(agent_loop, "generate_plugin_from_goal", lambda *_args, **_kwargs: Draft())
    monkeypatch.setattr(agent_loop, "save_generated_plugin", lambda _draft: plugin)
    monkeypatch.setattr(agent_loop.Confirm, "ask", lambda *args, **kwargs: "Generate plugin?" in str(args[0]))
    monkeypatch.setattr(agent_loop, "run_plugin", lambda *_args, **_kwargs: ran.__setitem__("called", True))

    result = process_agent_input("generate plugin for local report", SessionMemory(), session_id="agent-test", confirm_fn=lambda *_args: True)

    assert result.ok is False
    assert ran["called"] is False
