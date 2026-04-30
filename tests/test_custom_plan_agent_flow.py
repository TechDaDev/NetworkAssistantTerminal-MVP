from types import SimpleNamespace

from app.agent import agent_loop
from app.agent.agent_loop import process_agent_input
from app.agent.session_memory import SessionMemory


class Draft:
    has_missing_inputs = False
    missing_inputs = []


def test_agent_can_generate_and_save_custom_plan_from_mocked_deepseek(monkeypatch):
    plan = SimpleNamespace(id=42, title="Custom plan", description="policy", proposed_commands="ip route x", rollback_commands="no ip route x")
    monkeypatch.setattr(agent_loop, "log_agent_action", lambda **_kwargs: None)
    monkeypatch.setattr(agent_loop, "generate_custom_plan_from_goal", lambda *_args, **_kwargs: Draft())
    monkeypatch.setattr(agent_loop, "save_custom_plan", lambda _draft: plan)
    monkeypatch.setattr(agent_loop, "metadata_for_plan", lambda _plan: {"raw_json": {"ok": True}})
    monkeypatch.setattr(agent_loop.Confirm, "ask", lambda *_args, **_kwargs: False)

    result = process_agent_input(
        "configure Cisco static route device=192.168.88.20",
        SessionMemory(),
        session_id="agent-test",
        confirm_fn=lambda *_args: True,
    )

    assert result.action == "custom_plan_goal"
    assert result.ok is False
    assert result.data["plan_id"] == 42


def test_agent_does_not_execute_custom_plan_without_user_confirmation(monkeypatch):
    plan = SimpleNamespace(id=42, title="Custom plan", description="policy", proposed_commands="ip route x", rollback_commands="no ip route x")
    executed = {"called": False}
    monkeypatch.setattr(agent_loop, "log_agent_action", lambda **_kwargs: None)
    monkeypatch.setattr(agent_loop, "generate_custom_plan_from_goal", lambda *_args, **_kwargs: Draft())
    monkeypatch.setattr(agent_loop, "save_custom_plan", lambda _draft: plan)
    monkeypatch.setattr(agent_loop, "metadata_for_plan", lambda _plan: {"raw_json": {"ok": True}})
    monkeypatch.setattr(agent_loop.Confirm, "ask", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(agent_loop, "execute_change_plan", lambda *_args, **_kwargs: executed.__setitem__("called", True))

    process_agent_input(
        "configure MikroTik load balancing device=192.168.88.1",
        SessionMemory(),
        session_id="agent-test",
        confirm_fn=lambda *_args: True,
    )

    assert executed["called"] is False
