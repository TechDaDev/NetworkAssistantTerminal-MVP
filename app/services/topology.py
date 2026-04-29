from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.database import get_session, init_db
from app.models import (
    CommandRun,
    Device,
    ManualTopologyEdge,
    ManualTopologyNode,
    ManualTopologyNote,
    ScanRun,
    TopologyEdge,
    TopologyNode,
    TopologySnapshot,
)
from app.schemas import DiagnosticFinding, DiagnosticResult
from app.services.topology_parsers import (
    NeighborRecord,
    parse_cisco_cdp_neighbors,
    parse_cisco_lldp_neighbors,
    parse_mikrotik_arp,
)


@dataclass
class TopologyBuildResult:
    snapshot: TopologySnapshot
    warnings: list[str] = field(default_factory=list)


@dataclass
class TopologySnapshotResult:
    snapshot: TopologySnapshot
    nodes: list[TopologyNode]
    edges: list[TopologyEdge]


@dataclass
class _NodeDraft:
    node_key: str
    device_id: int | None
    ip_address: str | None
    mac_address: str | None
    label: str
    node_type: str
    vendor: str
    confidence: str
    evidence: str


@dataclass
class _EdgeDraft:
    source_node_key: str
    target_node_key: str
    relation_type: str
    confidence: str
    evidence_source: str
    evidence: str


def build_topology_snapshot() -> TopologyBuildResult:
    init_db()
    warnings: list[str] = []
    with get_session() as session:
        latest_scan = session.scalar(select(ScanRun).order_by(ScanRun.finished_at.desc()))
        devices = list(
            session.scalars(
                select(Device)
                .options(selectinload(Device.ports), selectinload(Device.observations), selectinload(Device.command_runs))
                .order_by(Device.ip_address)
            ).all()
        )
        nodes, edges = _build_drafts(latest_scan, devices, warnings)
        snapshot = _save_snapshot_from_drafts(session, nodes, edges, warnings, title="Local topology snapshot", source="local_inventory")
        return TopologyBuildResult(snapshot=_load_snapshot_result(session, snapshot.id).snapshot, warnings=warnings)


def rebuild_topology_with_manual() -> TopologyBuildResult:
    init_db()
    warnings: list[str] = []
    with get_session() as session:
        latest_scan = session.scalar(select(ScanRun).order_by(ScanRun.finished_at.desc()))
        devices = list(
            session.scalars(
                select(Device)
                .options(selectinload(Device.ports), selectinload(Device.observations), selectinload(Device.command_runs))
                .order_by(Device.ip_address)
            ).all()
        )
        manual_nodes = list(session.scalars(select(ManualTopologyNode).order_by(ManualTopologyNode.node_key)).all())
        manual_edges = list(session.scalars(select(ManualTopologyEdge).order_by(ManualTopologyEdge.source_node_key)).all())
        manual_notes = list(session.scalars(select(ManualTopologyNote).order_by(ManualTopologyNote.created_at)).all())
        nodes, edges = _build_drafts(latest_scan, devices, warnings)
        _apply_manual_overlays(nodes, edges, manual_nodes, manual_edges, manual_notes, warnings)
        snapshot = _save_snapshot_from_drafts(
            session,
            nodes,
            edges,
            warnings,
            title="Local topology snapshot with manual corrections",
            source="local_inventory+manual",
            summary_extra={
                "manual_node_count": len(manual_nodes),
                "manual_edge_count": len(manual_edges),
                "manual_note_count": len(manual_notes),
            },
        )
        return TopologyBuildResult(snapshot=_load_snapshot_result(session, snapshot.id).snapshot, warnings=warnings)


def get_latest_topology() -> TopologySnapshotResult | None:
    init_db()
    with get_session() as session:
        snapshot = session.scalar(select(TopologySnapshot).order_by(TopologySnapshot.created_at.desc()))
        if snapshot is None:
            return None
        return _load_snapshot_result(session, snapshot.id)


def get_topology(snapshot_id: int) -> TopologySnapshotResult:
    init_db()
    with get_session() as session:
        return _load_snapshot_result(session, snapshot_id)


def export_topology_json(snapshot_id: int | None = None) -> dict:
    result = _snapshot_or_latest(snapshot_id)
    return {
        "snapshot": {
            "id": result.snapshot.id,
            "title": result.snapshot.title,
            "source": result.snapshot.source,
            "created_at": result.snapshot.created_at.isoformat(),
            "summary": json.loads(result.snapshot.summary_json or "{}"),
        },
        "nodes": [_node_dict(node) for node in result.nodes],
        "edges": [_edge_dict(edge) for edge in result.edges],
    }


def export_topology_mermaid(snapshot_id: int | None = None) -> str:
    result = _snapshot_or_latest(snapshot_id)
    lines = ["graph TD"]
    for node in result.nodes:
        lines.append(f'    {_safe_mermaid_id(node.node_key)}["{_escape_mermaid(node.label)}"]')
    for edge in result.edges:
        label = f"{edge.relation_type}: {edge.confidence}"
        source = _safe_mermaid_id(edge.source_node_key)
        target = _safe_mermaid_id(edge.target_node_key)
        if edge.confidence == "high":
            lines.append(f'    {source} -->|"{_escape_mermaid(label)}"| {target}')
        else:
            lines.append(f'    {source} -. "{_escape_mermaid(label)}" .-> {target}')
    return "\n".join(lines)


def explain_topology(snapshot_id: int | None = None) -> DiagnosticResult:
    result = _snapshot_or_latest(snapshot_id)
    findings: list[DiagnosticFinding] = []
    high_edges = [edge for edge in result.edges if edge.confidence == "high"]
    low_edges = [edge for edge in result.edges if edge.confidence == "low"]
    findings.append(
        DiagnosticFinding(
            severity="info",
            title="Topology snapshot available",
            detail=f"Snapshot {result.snapshot.id} contains {len(result.nodes)} node(s) and {len(result.edges)} edge(s).",
        )
    )
    if high_edges:
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="High-confidence neighbor evidence",
                detail=f"{len(high_edges)} high-confidence edge(s) were built from direct evidence such as gateway, CDP, or LLDP.",
                evidence=[f"{edge.source_node_key} -> {edge.target_node_key} ({edge.evidence_source})" for edge in high_edges[:5]],
            )
        )
    if low_edges:
        findings.append(
            DiagnosticFinding(
                severity="low",
                title="Low-confidence inferred links",
                detail="Low-confidence links are inferred from same-subnet or ARP-only evidence and are not physical topology proof.",
                evidence=[f"{edge.source_node_key} -> {edge.target_node_key} ({edge.relation_type})" for edge in low_edges[:5]],
            )
        )
    manual_edges = [edge for edge in result.edges if edge.evidence_source == "manual"]
    manual_nodes = [node for node in result.nodes if "Manual confirmation" in (node.evidence or "")]
    if manual_edges or manual_nodes:
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="Manual topology corrections",
                detail="Manual nodes or edges are present. They supplement discovered evidence and are not auto-discovered.",
                evidence=[
                    *[f"node {node.node_key}" for node in manual_nodes[:3]],
                    *[f"{edge.source_node_key} -> {edge.target_node_key} ({edge.relation_type})" for edge in manual_edges[:5]],
                ][:8],
            )
        )
    if not any(edge.relation_type in {"cdp_neighbor", "lldp_neighbor"} for edge in result.edges):
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="No CDP/LLDP evidence",
                detail="No stored Cisco CDP/LLDP neighbor output was available. Physical topology confidence is limited.",
                recommendation="Run `python main.py connect collect <ip>` on lab switches/routers with stored credentials.",
            )
        )
    if not any(edge.relation_type == "arp_neighbor" for edge in result.edges):
        findings.append(
            DiagnosticFinding(
                severity="low",
                title="No ARP neighbor evidence",
                detail="No stored MikroTik `/ip arp print` evidence was available.",
                recommendation="Run `python main.py connect collect <ip>` on MikroTik routers with stored credentials.",
            )
        )
    return DiagnosticResult(
        title="Topology Explanation",
        summary="Topology is built from stored local evidence. Same-subnet and ARP edges are not proof of physical cabling.",
        findings=findings,
        suggested_commands=["python main.py scan", "python main.py enrich", "python main.py connect collect <ip>"],
    )


def latest_topology_context_summary() -> str:
    result = get_latest_topology()
    if result is None:
        return "# Latest Topology Summary\nNo topology snapshot has been built."
    high = [edge for edge in result.edges if edge.confidence == "high"]
    low = [edge for edge in result.edges if edge.confidence == "low"]
    return (
        "# Latest Topology Summary\n"
        f"Snapshot ID: {result.snapshot.id}\n"
        f"Nodes: {len(result.nodes)}\n"
        f"Edges: {len(result.edges)}\n"
        "High-confidence links:\n"
        + "\n".join(f"- {edge.source_node_key} -> {edge.target_node_key} ({edge.relation_type}, {edge.evidence_source})" for edge in high[:5])
        + ("\n" if high else "- none\n")
        + "Low-confidence inferred links:\n"
        + "\n".join(f"- {edge.source_node_key} -> {edge.target_node_key} ({edge.relation_type})" for edge in low[:5])
        + ("\n" if low else "- none\n")
    )


def _build_drafts(
    latest_scan: ScanRun | None,
    devices: list[Device],
    warnings: list[str],
) -> tuple[dict[str, _NodeDraft], list[_EdgeDraft]]:
    nodes: dict[str, _NodeDraft] = {}
    edges: list[_EdgeDraft] = []
    ip_to_key: dict[str, str] = {}
    local_key = "local_host"
    gateway_ip = latest_scan.gateway_ip if latest_scan else None
    cidr = latest_scan.cidr if latest_scan else None
    if latest_scan:
        nodes[local_key] = _NodeDraft(
            node_key=local_key,
            device_id=None,
            ip_address=latest_scan.local_ip,
            mac_address=None,
            label=f"Local Host {latest_scan.local_ip}",
            node_type="local_host",
            vendor="Local",
            confidence="high",
            evidence=f"Latest scan interface {latest_scan.interface_name}",
        )
        ip_to_key[latest_scan.local_ip] = local_key

    for device in devices:
        key = _device_key(device.ip_address)
        ip_to_key[device.ip_address] = key
        node_type = _node_type(device, gateway_ip)
        nodes[key] = _NodeDraft(
            node_key=key,
            device_id=device.id,
            ip_address=device.ip_address,
            mac_address=device.mac_address,
            label=f"{device.ip_address} {node_type}",
            node_type=node_type,
            vendor=device.vendor_guess,
            confidence=_confidence(device.confidence),
            evidence=f"Inventory device: vendor={device.vendor_guess}, type={device.device_type_guess}",
        )

    gateway_key = None
    if gateway_ip:
        gateway_key = ip_to_key.get(gateway_ip, _gateway_key(gateway_ip))
        if gateway_key not in nodes:
            nodes[gateway_key] = _NodeDraft(
                node_key=gateway_key,
                device_id=None,
                ip_address=gateway_ip,
                mac_address=None,
                label=f"Gateway {gateway_ip}",
                node_type="gateway",
                vendor="Unknown",
                confidence="medium",
                evidence="Gateway from latest scan; not necessarily discovered as live host.",
            )
            ip_to_key[gateway_ip] = gateway_key
        edges.append(_EdgeDraft(local_key, gateway_key, "default_gateway", "high", "latest_scan", f"Default gateway {gateway_ip} from latest scan."))

    if gateway_key and cidr:
        for device in devices:
            if device.ip_address == gateway_ip:
                continue
            if _same_cidr(device.ip_address, cidr):
                edges.append(
                    _EdgeDraft(
                        gateway_key,
                        ip_to_key[device.ip_address],
                        "same_subnet",
                        "low",
                        "inventory",
                        "Weak inferred layer-3 relation only; not physical topology proof.",
                    )
                )

    for device in devices:
        source_key = ip_to_key.get(device.ip_address)
        if not source_key:
            continue
        history = _latest_successful_outputs(device.command_runs)
        for command, parser, relation in (
            ("show cdp neighbors detail", parse_cisco_cdp_neighbors, "cdp_neighbor"),
            ("show lldp neighbors detail", parse_cisco_lldp_neighbors, "lldp_neighbor"),
        ):
            output = history.get(command)
            if output:
                for neighbor in parser(output):
                    target_key = _neighbor_node(nodes, ip_to_key, neighbor)
                    edges.append(
                        _EdgeDraft(
                            source_key,
                            target_key,
                            relation,
                            "high",
                            command,
                            _neighbor_evidence(neighbor),
                        )
                    )
        arp_output = history.get("/ip arp print")
        if arp_output:
            for arp in parse_mikrotik_arp(arp_output):
                target_key = ip_to_key.get(arp.ip_address)
                confidence = "medium" if target_key else "low"
                if target_key is None:
                    target_key = _arp_key(arp.ip_address)
                    nodes.setdefault(
                        target_key,
                        _NodeDraft(
                            node_key=target_key,
                            device_id=None,
                            ip_address=arp.ip_address,
                            mac_address=arp.mac_address,
                            label=f"ARP {arp.ip_address}",
                            node_type="unknown",
                            vendor="Unknown",
                            confidence="low",
                            evidence="ARP-only node from MikroTik /ip arp print.",
                        ),
                    )
                    ip_to_key[arp.ip_address] = target_key
                edges.append(
                    _EdgeDraft(
                        source_key,
                        target_key,
                        "arp_neighbor",
                        confidence,
                        "/ip arp print",
                        f"ARP entry ip={arp.ip_address}, mac={arp.mac_address or '--'}, interface={arp.interface or '--'}. Not physical topology proof.",
                    )
                )
    if not latest_scan:
        warnings.append("No latest scan is stored; local host and gateway evidence is unavailable.")
    return nodes, edges


def _apply_manual_overlays(
    nodes: dict[str, _NodeDraft],
    edges: list[_EdgeDraft],
    manual_nodes: list[ManualTopologyNode],
    manual_edges: list[ManualTopologyEdge],
    manual_notes: list[ManualTopologyNote],
    warnings: list[str],
) -> None:
    for manual in manual_nodes:
        evidence = "Manual confirmation, not auto-discovered."
        if manual.notes:
            evidence += f" Notes: {manual.notes}"
        if manual.node_key in nodes:
            nodes[manual.node_key].label = manual.label
            nodes[manual.node_key].node_type = manual.node_type
            nodes[manual.node_key].vendor = manual.vendor or nodes[manual.node_key].vendor
            nodes[manual.node_key].confidence = "high"
            nodes[manual.node_key].evidence = f"{nodes[manual.node_key].evidence}\n{evidence}"
            if manual.ip_address:
                nodes[manual.node_key].ip_address = manual.ip_address
            if manual.mac_address:
                nodes[manual.node_key].mac_address = manual.mac_address
        else:
            nodes[manual.node_key] = _NodeDraft(
                node_key=manual.node_key,
                device_id=None,
                ip_address=manual.ip_address,
                mac_address=manual.mac_address,
                label=manual.label,
                node_type=manual.node_type,
                vendor=manual.vendor or "Unknown",
                confidence="high",
                evidence=evidence,
            )

    existing_keys = set(nodes)
    for manual in manual_edges:
        if manual.source_node_key not in existing_keys:
            warnings.append(f"Manual edge source `{manual.source_node_key}` does not match a topology node.")
        if manual.target_node_key not in existing_keys:
            warnings.append(f"Manual edge target `{manual.target_node_key}` does not match a topology node.")
        evidence = "Manual confirmation, not auto-discovered."
        if manual.label:
            evidence += f" Label: {manual.label}."
        if manual.notes:
            evidence += f" Notes: {manual.notes}"
        edges.append(
            _EdgeDraft(
                source_node_key=manual.source_node_key,
                target_node_key=manual.target_node_key,
                relation_type=manual.relation_type,
                confidence=manual.confidence,
                evidence_source="manual",
                evidence=evidence,
            )
        )

    topology_notes: list[str] = []
    for note in manual_notes:
        if note.target_type == "topology":
            topology_notes.append(note.note)
        elif note.target_type == "node" and note.target_key in nodes:
            nodes[note.target_key].evidence = f"{nodes[note.target_key].evidence}\nManual note: {note.note}"
        elif note.target_type == "edge":
            _apply_manual_edge_note(edges, note.target_key, note.note)
        else:
            warnings.append(f"Manual note {note.id} target was not found in this snapshot.")
    for note in topology_notes:
        warnings.append(f"Manual topology note: {note}")


def _apply_manual_edge_note(edges: list[_EdgeDraft], target_key: str | None, note: str) -> None:
    if not target_key:
        return
    for edge in edges:
        edge_key = f"{edge.source_node_key}->{edge.target_node_key}"
        if target_key == edge_key:
            edge.evidence = f"{edge.evidence}\nManual note: {note}"


def _save_snapshot_from_drafts(
    session,
    nodes: dict[str, _NodeDraft],
    edges: list[_EdgeDraft],
    warnings: list[str],
    *,
    title: str,
    source: str,
    summary_extra: dict | None = None,
) -> TopologySnapshot:
    summary = _summary(nodes, edges, warnings)
    if summary_extra:
        summary.update(summary_extra)
    snapshot = TopologySnapshot(
        title=title,
        source=source,
        summary_json=json.dumps(summary),
    )
    session.add(snapshot)
    session.flush()
    for node in nodes.values():
        session.add(TopologyNode(snapshot_id=snapshot.id, **node.__dict__))
    for edge in _dedupe_edges(edges):
        session.add(TopologyEdge(snapshot_id=snapshot.id, **edge.__dict__))
    session.commit()
    return snapshot


def _neighbor_node(nodes: dict[str, _NodeDraft], ip_to_key: dict[str, str], neighbor: NeighborRecord) -> str:
    if neighbor.management_ip and neighbor.management_ip in ip_to_key:
        return ip_to_key[neighbor.management_ip]
    key = _device_key(neighbor.management_ip) if neighbor.management_ip else _label_key(neighbor.name)
    nodes.setdefault(
        key,
        _NodeDraft(
            node_key=key,
            device_id=None,
            ip_address=neighbor.management_ip,
            mac_address=None,
            label=neighbor.name,
            node_type=_platform_type(neighbor.platform),
            vendor=_platform_vendor(neighbor.platform),
            confidence="medium",
            evidence=f"Neighbor from CDP/LLDP: platform={neighbor.platform or '--'}",
        ),
    )
    if neighbor.management_ip:
        ip_to_key[neighbor.management_ip] = key
    return key


def _latest_successful_outputs(command_runs: list[CommandRun]) -> dict[str, str]:
    outputs: dict[str, str] = {}
    for run in sorted(command_runs, key=lambda item: item.started_at, reverse=True):
        if run.success and run.command not in outputs:
            outputs[run.command] = run.output or ""
    return outputs


def _node_type(device: Device, gateway_ip: str | None) -> str:
    text = f"{device.vendor_guess} {device.device_type_guess}".lower()
    if gateway_ip and device.ip_address == gateway_ip:
        return "gateway"
    if "switch" in text:
        return "switch"
    if "router" in text or "gateway" in text or "mikrotik" in text:
        return "router"
    if "access point" in text or "ap" == device.device_type_guess.lower():
        return "access_point"
    if "server" in text or any(port.port in {22, 80, 443, 445, 3389} for port in device.ports):
        return "server"
    if "client" in text:
        return "client"
    return "unknown"


def _platform_type(platform: str | None) -> str:
    text = (platform or "").lower()
    if "switch" in text or "catalyst" in text:
        return "switch"
    if "router" in text or "ios" in text or "mikrotik" in text:
        return "router"
    return "unknown"


def _platform_vendor(platform: str | None) -> str:
    text = (platform or "").lower()
    if "cisco" in text or "ios" in text or "catalyst" in text:
        return "Cisco"
    if "mikrotik" in text or "routeros" in text:
        return "MikroTik"
    return "Unknown"


def _summary(nodes: dict[str, _NodeDraft], edges: list[_EdgeDraft], warnings: list[str]) -> dict:
    confidence: dict[str, int] = {}
    for edge in edges:
        confidence[edge.confidence] = confidence.get(edge.confidence, 0) + 1
    return {"node_count": len(nodes), "edge_count": len(_dedupe_edges(edges)), "edge_confidence": confidence, "warnings": warnings}


def _load_snapshot_result(session, snapshot_id: int) -> TopologySnapshotResult:
    snapshot = session.scalar(select(TopologySnapshot).where(TopologySnapshot.id == snapshot_id))
    if snapshot is None:
        raise ValueError(f"Topology snapshot {snapshot_id} not found.")
    nodes = list(session.scalars(select(TopologyNode).where(TopologyNode.snapshot_id == snapshot_id).order_by(TopologyNode.node_key)).all())
    edges = list(session.scalars(select(TopologyEdge).where(TopologyEdge.snapshot_id == snapshot_id).order_by(TopologyEdge.source_node_key, TopologyEdge.target_node_key)).all())
    return TopologySnapshotResult(snapshot=snapshot, nodes=nodes, edges=edges)


def _snapshot_or_latest(snapshot_id: int | None) -> TopologySnapshotResult:
    if snapshot_id is not None:
        return get_topology(snapshot_id)
    result = get_latest_topology()
    if result is None:
        raise ValueError("No topology snapshot exists. Run `python main.py topology build` first.")
    return result


def _dedupe_edges(edges: list[_EdgeDraft]) -> list[_EdgeDraft]:
    seen: set[tuple[str, str, str, str]] = set()
    deduped: list[_EdgeDraft] = []
    for edge in edges:
        key = (edge.source_node_key, edge.target_node_key, edge.relation_type, edge.evidence_source)
        if key not in seen and edge.source_node_key != edge.target_node_key:
            seen.add(key)
            deduped.append(edge)
    return deduped


def _node_dict(node: TopologyNode) -> dict:
    return {
        "key": node.node_key,
        "device_id": node.device_id,
        "ip_address": node.ip_address,
        "mac_address": node.mac_address,
        "label": node.label,
        "node_type": node.node_type,
        "vendor": node.vendor,
        "confidence": node.confidence,
        "evidence": node.evidence,
    }


def _edge_dict(edge: TopologyEdge) -> dict:
    return {
        "source": edge.source_node_key,
        "target": edge.target_node_key,
        "relation_type": edge.relation_type,
        "confidence": edge.confidence,
        "evidence_source": edge.evidence_source,
        "evidence": edge.evidence,
    }


def _same_cidr(ip_address: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip_address) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _confidence(value: str) -> str:
    lowered = (value or "").lower()
    return lowered if lowered in {"low", "medium", "high"} else "low"


def _neighbor_evidence(neighbor: NeighborRecord) -> str:
    return (
        f"neighbor={neighbor.name}, local_interface={neighbor.local_interface or '--'}, "
        f"neighbor_interface={neighbor.neighbor_interface or '--'}, management_ip={neighbor.management_ip or '--'}, "
        f"platform={neighbor.platform or '--'}"
    )


def _device_key(ip_address: str) -> str:
    return "device_" + ip_address.replace(".", "_").replace(":", "_")


def _gateway_key(ip_address: str) -> str:
    return "gateway_" + ip_address.replace(".", "_")


def _arp_key(ip_address: str) -> str:
    return "arp_" + ip_address.replace(".", "_")


def _label_key(label: str) -> str:
    return "neighbor_" + re.sub(r"[^A-Za-z0-9_]+", "_", label.strip()).strip("_").lower()


def _safe_mermaid_id(key: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", key)


def _escape_mermaid(value: str) -> str:
    return value.replace('"', "'")
