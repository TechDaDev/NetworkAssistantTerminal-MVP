from datetime import datetime, timezone

from app import server
from app.agent.intent_parser import parse_intent
from app.models import TopologyEdge, TopologyNode, TopologySnapshot
from app.services import topology_exporter
from app.services.topology import TopologySnapshotResult
from app.services.topology_exporter import render_topology_report, write_topology_report_file


def _fake_result() -> TopologySnapshotResult:
    snapshot = TopologySnapshot(id=12, title="test", source="unit", created_at=datetime.now(timezone.utc), summary_json="{}")
    nodes = [
        TopologyNode(snapshot_id=12, node_key="gateway", label="Gateway", node_type="gateway", vendor="Cisco", confidence="high"),
        TopologyNode(snapshot_id=12, node_key="client", label="Client", node_type="client", vendor="Unknown", confidence="low"),
    ]
    edges = [
        TopologyEdge(snapshot_id=12, source_node_key="gateway", target_node_key="client", relation_type="same_subnet", confidence="low", evidence_source="inventory", evidence="inferred")
    ]
    return TopologySnapshotResult(snapshot=snapshot, nodes=nodes, edges=edges)


def test_report_markdown_includes_required_sections(monkeypatch):
    monkeypatch.setattr(topology_exporter, "_snapshot_or_latest", lambda snapshot_id=None: _fake_result())
    monkeypatch.setattr(topology_exporter, "export_topology_mermaid", lambda snapshot_id=None: "graph TD\n gateway -.-> client")

    report = render_topology_report()

    for section in (
        "## Executive Summary",
        "## Snapshot Metadata",
        "## Topology Diagram",
        "## Known Devices",
        "## Links and Edges",
        "## High-Confidence Evidence",
        "## Low-Confidence Inferred Links",
        "## Manual Corrections",
        "## Missing Evidence",
        "## Recommended Next Commands",
    ):
        assert section in report


def test_report_file_export_works(monkeypatch, tmp_path):
    monkeypatch.setattr(topology_exporter, "_snapshot_or_latest", lambda snapshot_id=None: _fake_result())
    monkeypatch.setattr(topology_exporter, "export_topology_mermaid", lambda snapshot_id=None: "graph TD\n gateway -.-> client")
    output = tmp_path / "network_topology_report.md"

    result = write_topology_report_file(output_path=output)

    assert result.snapshot_id == 12
    assert "Network Topology Report" in output.read_text()


def test_server_report_endpoint_returns_markdown(monkeypatch):
    monkeypatch.setattr(server, "render_topology_report", lambda snapshot_id=None: "# Network Topology Report")

    response = server.topology_report_endpoint()

    assert response["ok"] is True
    assert response["content"].startswith("# Network Topology Report")


def test_agent_routes_export_and_report_paths():
    export_intent = parse_intent("export topology mermaid to topology.md")
    report_intent = parse_intent("topology report to network_topology_report.md")

    assert export_intent.tool_name == "export_topology_file"
    assert export_intent.args["format"] == "mermaid"
    assert export_intent.args["output"] == "topology.md"
    assert report_intent.tool_name == "topology_report_file"
