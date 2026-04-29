from app.models import ManualTopologyEdge, ManualTopologyNode, ManualTopologyNote
from app.services.topology import _EdgeDraft, _NodeDraft, _apply_manual_overlays


def test_rebuild_overlay_includes_manual_nodes_and_edges():
    nodes = {
        "gateway_192_168_88_1": _NodeDraft(
            node_key="gateway_192_168_88_1",
            device_id=None,
            ip_address="192.168.88.1",
            mac_address=None,
            label="Gateway",
            node_type="gateway",
            vendor="Unknown",
            confidence="medium",
            evidence="latest scan",
        )
    }
    edges: list[_EdgeDraft] = []
    warnings: list[str] = []
    manual_nodes = [
        ManualTopologyNode(
            node_key="core-switch",
            label="Core Switch",
            node_type="switch",
            ip_address="192.168.88.2",
            vendor="Cisco",
            notes="Located in lab rack",
        )
    ]
    manual_edges = [
        ManualTopologyEdge(
            source_node_key="gateway_192_168_88_1",
            target_node_key="core-switch",
            relation_type="manual",
            confidence="high",
            label="uplink ether2",
        )
    ]

    _apply_manual_overlays(nodes, edges, manual_nodes, manual_edges, [], warnings)

    assert "core-switch" in nodes
    assert nodes["core-switch"].confidence == "high"
    assert "Manual confirmation" in nodes["core-switch"].evidence
    assert edges[0].evidence_source == "manual"
    assert edges[0].confidence == "high"


def test_manual_notes_attach_to_nodes_and_edges():
    nodes = {
        "core-switch": _NodeDraft("core-switch", None, None, None, "Core Switch", "switch", "Cisco", "high", "manual")
    }
    edges = [_EdgeDraft("gateway", "core-switch", "manual", "high", "manual", "Manual confirmation")]
    notes = [
        ManualTopologyNote(target_type="node", target_key="core-switch", note="rack A"),
        ManualTopologyNote(target_type="edge", target_key="gateway->core-switch", note="confirmed cable"),
    ]
    warnings: list[str] = []

    _apply_manual_overlays(nodes, edges, [], [], notes, warnings)

    assert "Manual note: rack A" in nodes["core-switch"].evidence
    assert "Manual note: confirmed cable" in edges[0].evidence
