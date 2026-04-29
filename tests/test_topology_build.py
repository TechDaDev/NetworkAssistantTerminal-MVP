from app.services.topology import _build_drafts
from tests.topology_test_utils import fake_devices, fake_scan


def test_topology_build_creates_local_gateway_and_device_nodes():
    warnings = []
    nodes, edges = _build_drafts(fake_scan(), fake_devices(), warnings)

    assert "local_host" in nodes
    assert "device_192_168_88_1" in nodes
    assert "device_192_168_88_20" in nodes
    assert any(edge.relation_type == "default_gateway" for edge in edges)


def test_same_subnet_edges_are_low_confidence():
    warnings = []
    _nodes, edges = _build_drafts(fake_scan(), fake_devices(), warnings)

    same_subnet = [edge for edge in edges if edge.relation_type == "same_subnet"]

    assert same_subnet
    assert all(edge.confidence == "low" for edge in same_subnet)


def test_cdp_edges_are_high_confidence():
    warnings = []
    _nodes, edges = _build_drafts(fake_scan(), fake_devices(), warnings)

    cdp = [edge for edge in edges if edge.relation_type == "cdp_neighbor"]

    assert cdp
    assert all(edge.confidence == "high" for edge in cdp)


def test_arp_only_edges_are_not_high_confidence():
    warnings = []
    _nodes, edges = _build_drafts(fake_scan(), fake_devices(), warnings)

    arp = [edge for edge in edges if edge.relation_type == "arp_neighbor"]

    assert arp
    assert all(edge.confidence in {"low", "medium"} for edge in arp)
