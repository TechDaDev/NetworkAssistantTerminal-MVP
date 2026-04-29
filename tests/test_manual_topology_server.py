import pytest
from fastapi import HTTPException

from app import server
from app.models import ManualTopologyNode
from app.services.manual_topology import ManualTopologyOperationResult


def test_server_manual_node_add_endpoint(monkeypatch):
    node = ManualTopologyNode(id=1, node_key="core-switch", label="Core Switch", node_type="switch")

    def fake_add_manual_node(**_kwargs):
        return ManualTopologyOperationResult(True, "added", item=node)

    monkeypatch.setattr(server, "add_manual_node", fake_add_manual_node)

    response = server.topology_manual_node_add_endpoint(
        server.ManualTopologyNodeRequest(node_key="core-switch", label="Core Switch", node_type="switch")
    )

    assert response["ok"] is True
    assert response["node"]["node_key"] == "core-switch"


def test_server_manual_delete_requires_confirmation():
    with pytest.raises(HTTPException) as exc_info:
        server.topology_manual_node_delete_endpoint(1, confirm=False)

    assert exc_info.value.status_code == 400
    assert "confirmation" in exc_info.value.detail.lower()
