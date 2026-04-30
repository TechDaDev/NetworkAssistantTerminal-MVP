from fastapi import HTTPException

from app import server


def test_plugin_server_endpoints(monkeypatch):
    plugin = type("Plugin", (), {
        "id": 1,
        "tool_name": "safe_reporter",
        "version": "0.1.0",
        "description": "safe",
        "category": "reporter",
        "risk_level": "low",
        "status": "pending",
        "file_path": "plugins/pending/safe_reporter.py",
        "source": "llm_generated",
        "validation_status": "passed",
        "validation_report": "ok",
        "created_at": None,
        "updated_at": None,
        "approved_at": None,
        "disabled_at": None,
    })()
    monkeypatch.setattr(server, "list_plugins", lambda status=None: [plugin])
    monkeypatch.setattr(server, "get_plugin", lambda tool_name: plugin if tool_name == "safe_reporter" else None)
    monkeypatch.setattr(server, "validate_plugin", lambda tool_name: plugin)
    monkeypatch.setattr(server, "approve_plugin", lambda tool_name: plugin)
    monkeypatch.setattr(server, "reject_plugin", lambda tool_name: plugin)
    monkeypatch.setattr(server, "disable_plugin", lambda tool_name: plugin)

    assert server.plugins_endpoint()["plugins"][0]["tool_name"] == "safe_reporter"
    assert server.plugin_show_endpoint("safe_reporter")["ok"] is True
    assert server.plugin_validate_endpoint("safe_reporter")["ok"] is True
    assert server.plugin_approve_endpoint("safe_reporter")["ok"] is True
    assert server.plugin_reject_endpoint("safe_reporter")["ok"] is True
    assert server.plugin_disable_endpoint("safe_reporter")["ok"] is True


def test_plugin_show_404(monkeypatch):
    monkeypatch.setattr(server, "get_plugin", lambda tool_name: None)

    try:
        server.plugin_show_endpoint("missing")
    except HTTPException as exc:
        assert exc.status_code == 404
