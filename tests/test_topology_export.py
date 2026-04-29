from datetime import datetime, timezone

from app.models import TopologyEdge, TopologyNode, TopologySnapshot
from app.services.topology import TopologySnapshotResult, export_topology_json, export_topology_mermaid


def _fake_result() -> TopologySnapshotResult:
    snapshot = TopologySnapshot(id=1, title="test", source="unit", created_at=datetime.now(timezone.utc), summary_json="{}")
    nodes = [
        TopologyNode(snapshot_id=1, node_key="local_host", label="Local Host", node_type="local_host", vendor="Local", confidence="high"),
        TopologyNode(snapshot_id=1, node_key="gateway_192_168_88_1", label="Gateway 192.168.88.1", node_type="gateway", vendor="Unknown", confidence="medium"),
    ]
    edges = [
        TopologyEdge(
            snapshot_id=1,
            source_node_key="local_host",
            target_node_key="gateway_192_168_88_1",
            relation_type="default_gateway",
            confidence="high",
            evidence_source="latest_scan",
            evidence="gateway",
        )
    ]
    return TopologySnapshotResult(snapshot=snapshot, nodes=nodes, edges=edges)


def test_mermaid_export_contains_expected_nodes_and_edges(monkeypatch):
    monkeypatch.setattr("app.services.topology._snapshot_or_latest", lambda snapshot_id: _fake_result())

    output = export_topology_mermaid()

    assert "graph TD" in output
    assert "local_host" in output
    assert "default_gateway: high" in output


def test_json_export_is_valid_shape(monkeypatch):
    monkeypatch.setattr("app.services.topology._snapshot_or_latest", lambda snapshot_id: _fake_result())

    data = export_topology_json()

    assert data["snapshot"]["id"] == 1
    assert data["nodes"][0]["key"] == "local_host"
    assert data["edges"][0]["relation_type"] == "default_gateway"
