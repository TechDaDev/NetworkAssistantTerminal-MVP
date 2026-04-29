import pytest
from fastapi import HTTPException

from app import server
from app.services.config_executor import ConfigExecutionError


def test_server_execute_endpoint_requires_confirmation(monkeypatch):
    def fake_execute_change_plan(plan_id, dry_run=False, confirmation=None):
        if confirmation != f"EXECUTE PLAN {plan_id}":
            raise ConfigExecutionError(f"Confirmation must exactly match `EXECUTE PLAN {plan_id}`.")

    monkeypatch.setattr(server, "execute_change_plan", fake_execute_change_plan)

    with pytest.raises(HTTPException) as exc_info:
        server.plan_execute_endpoint(5, server.PlanExecutionRequest(), dry_run=False)

    assert exc_info.value.status_code == 400
    assert "Confirmation must exactly match" in exc_info.value.detail
