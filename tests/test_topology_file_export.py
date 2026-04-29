import json
from datetime import datetime, timezone

import pytest

from app.models import TopologyEdge, TopologyNode, TopologySnapshot
from app.services import topology_exporter
from app.services.topology import TopologySnapshotResult
from app.services.topology_exporter import TopologyExportError, render_topology_html, render_topology_json, render_topology_markdown, write_topology_export_file


def _fake_result() -> TopologySnapshotResult:
    snapshot = TopologySnapshot(
        id=7,
        title="test",
        source="local_inventory+manual",
        created_at=datetime.now(timezone.utc),
        summary_json='{"edge_confidence": {"high": 1}, "warnings": ["missing cdp"]}',
    )
    nodes = [
        TopologyNode(snapshot_id=7, node_key="gateway", label="Gateway", node_type="gateway", vendor="Cisco", confidence="high", ip_address="192.168.88.1"),
        TopologyNode(snapshot_id=7, node_key="switch", label="Core Switch", node_type="switch", vendor="Cisco", confidence="high", evidence="Manual confirmation, not auto-discovered."),
    ]
    edges = [
        TopologyEdge(snapshot_id=7, source_node_key="gateway", target_node_key="switch", relation_type="manual", confidence="high", evidence_source="manual", evidence="Manual confirmation.")
    ]
    return TopologySnapshotResult(snapshot=snapshot, nodes=nodes, edges=edges)


@pytest.fixture(autouse=True)
def fake_topology(monkeypatch):
    result = _fake_result()
    monkeypatch.setattr(topology_exporter, "_snapshot_or_latest", lambda snapshot_id=None: result)
    monkeypatch.setattr(topology_exporter, "export_topology_mermaid", lambda snapshot_id=None: "graph TD\n    gateway --> switch")
    monkeypatch.setattr(
        topology_exporter,
        "export_topology_json",
        lambda snapshot_id=None: {
            "snapshot": {
                "id": result.snapshot.id,
                "created_at": result.snapshot.created_at.isoformat(),
                "source": result.snapshot.source,
                "summary": {"edge_confidence": {"high": 1}, "warnings": ["missing cdp"]},
            },
            "nodes": [{"key": "switch", "evidence": "Manual confirmation, not auto-discovered."}],
            "edges": [{"source": "gateway", "target": "switch", "evidence_source": "manual"}],
        },
    )


def test_mermaid_markdown_file_export_works(tmp_path):
    output = tmp_path / "topology.md"

    result = write_topology_export_file(export_format="mermaid", output_path=output)

    assert result.output_path == output
    text = output.read_text()
    assert "# Network Topology" in text
    assert "```mermaid" in text
    assert "## Nodes" in text


def test_json_file_export_works_and_is_valid_json(tmp_path):
    output = tmp_path / "topology.json"

    write_topology_export_file(export_format="json", output_path=output)

    data = json.loads(output.read_text())
    assert data["snapshot_id"] == 7
    assert data["manual_overlays"]["edge_count"] == 1


def test_html_export_works(tmp_path):
    output = tmp_path / "topology.html"

    write_topology_export_file(export_format="html", output_path=output)

    text = output.read_text()
    assert "<html" in text
    assert "cdn.jsdelivr.net" in text


def test_offline_html_does_not_include_cdn():
    text = render_topology_html(offline=True)

    assert "cdn.jsdelivr.net" not in text
    assert "<pre>" in text


def test_existing_file_overwrite_is_blocked_without_force(tmp_path):
    output = tmp_path / "topology.md"
    output.write_text("old")

    with pytest.raises(TopologyExportError):
        write_topology_export_file(export_format="mermaid", output_path=output)


def test_existing_file_overwrite_works_with_force(tmp_path):
    output = tmp_path / "topology.md"
    output.write_text("old")

    write_topology_export_file(export_format="mermaid", output_path=output, force=True)

    assert "# Network Topology" in output.read_text()


def test_unsupported_format_is_rejected(tmp_path):
    with pytest.raises(TopologyExportError):
        write_topology_export_file(export_format="pdf", output_path=tmp_path / "topology.pdf")


def test_render_json_and_markdown_include_manual_evidence():
    assert "Manual Evidence Notes" in render_topology_markdown()
    assert json.loads(render_topology_json())["manual_overlays"]["node_count"] == 1
