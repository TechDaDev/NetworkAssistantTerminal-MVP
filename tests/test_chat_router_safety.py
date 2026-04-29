from types import SimpleNamespace

from app.services import command_router


def test_chat_refuses_execute_plan():
    result = command_router.route_local_command("execute plan 5")

    assert not result.ok
    assert "direct CLI confirmation" in result.message


def test_chat_refuses_rollback_plan():
    result = command_router.route_local_command("rollback plan 5")

    assert not result.ok
    assert "Rollback requires direct CLI confirmation" in result.message


def test_chat_refuses_mikrotik_save_with_routeros_message(monkeypatch):
    monkeypatch.setattr(
        command_router,
        "get_change_plan",
        lambda plan_id: SimpleNamespace(plan_type="mikrotik_address"),
    )

    result = command_router.route_local_command("save plan 5")

    assert not result.ok
    assert "MikroTik changes are applied immediately" in result.message
