from datetime import datetime, timezone

from app.models import TopologyEdge, TopologyNode, TopologySnapshot
from app.services.topology import TopologySnapshotResult, export_topology_json, export_topology_mermaid


def _manual_result() -> TopologySnapshotResult:
    snapshot = TopologySnapshot(
        id=44,
        title="manual",
        source="local_inventory+manual",
        created_at=datetime.now(timezone.utc),
        summary_json='{"manual_edge_count": 1}',
    )
    nodes = [
        TopologyNode(snapshot_id=44, node_key="gateway", label="Gateway", node_type="gateway", vendor="Unknown", confidence="high"),
        TopologyNode(snapshot_id=44, node_key="core-switch", label="Core Switch", node_type="switch", vendor="Cisco", confidence="high"),
    ]
    edges = [
        TopologyEdge(
            snapshot_id=44,
            source_node_key="gateway",
            target_node_key="core-switch",
            relation_type="manual",
            confidence="high",
            evidence_source="manual",
            evidence="Manual confirmation, not auto-discovered.",
        )
    ]
    return TopologySnapshotResult(snapshot=snapshot, nodes=nodes, edges=edges)


def test_manual_edges_export_to_mermaid(monkeypatch):
    monkeypatch.setattr("app.services.topology._snapshot_or_latest", lambda snapshot_id: _manual_result())

    output = export_topology_mermaid()

    assert "core_switch" in output
    assert "manual: high" in output


def test_manual_data_is_marked_in_json(monkeypatch):
    monkeypatch.setattr("app.services.topology._snapshot_or_latest", lambda snapshot_id: _manual_result())

    data = export_topology_json()

    assert data["snapshot"]["source"] == "local_inventory+manual"
    assert data["edges"][0]["evidence_source"] == "manual"
    assert "not auto-discovered" in data["edges"][0]["evidence"]
