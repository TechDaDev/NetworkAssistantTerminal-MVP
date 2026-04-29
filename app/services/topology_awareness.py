from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.database import get_session, init_db
from app.models import (
    ChangePlan,
    Device,
    ManualTopologyEdge,
    ManualTopologyNode,
    ManualTopologyNote,
    TopologyEdge,
    TopologyNode,
    TopologySnapshot,
)
from app.schemas import DiagnosticFinding


UPLINK_TERMS = ("wan", "ether1", "sfp", "uplink", "trunk", "core", "internet")
ACCESS_TERMS = ("lan", "bridge", "br-lan", "ether2", "ether3", "ether4", "ether5", "access", "client")
INFRA_TERMS = ("uplink", "trunk", "core", "switch", "router", "ap", "gateway")
DO_NOT_MODIFY_TERMS = ("do not modify", "do-not-modify", "do not change", "do-not-change", "do not touch", "do-not-touch")


@dataclass
class TopologyPlanningContext:
    device_ip: str
    device: Device | None = None
    snapshot: TopologySnapshot | None = None
    nodes: list[TopologyNode] = field(default_factory=list)
    edges: list[TopologyEdge] = field(default_factory=list)
    manual_nodes: list[ManualTopologyNode] = field(default_factory=list)
    manual_edges: list[ManualTopologyEdge] = field(default_factory=list)
    manual_notes: list[ManualTopologyNote] = field(default_factory=list)
    known_devices: list[Device] = field(default_factory=list)

    @property
    def device_node_keys(self) -> set[str]:
        keys = {f"device_{self.device_ip.replace('.', '_').replace(':', '_')}"}
        if self.device:
            keys.update(node.node_key for node in self.nodes if node.device_id == self.device.id)
        keys.update(node.node_key for node in self.nodes if node.ip_address == self.device_ip)
        keys.update(node.node_key for node in self.manual_nodes if node.ip_address == self.device_ip)
        return keys


def get_topology_context_for_device(device_ip: str) -> TopologyPlanningContext:
    init_db()
    with get_session() as session:
        device = session.scalar(select(Device).where(Device.ip_address == device_ip))
        snapshot = session.scalar(select(TopologySnapshot).order_by(TopologySnapshot.created_at.desc()))
        nodes: list[TopologyNode] = []
        edges: list[TopologyEdge] = []
        if snapshot is not None:
            nodes = list(
                session.scalars(
                    select(TopologyNode)
                    .where(TopologyNode.snapshot_id == snapshot.id)
                    .order_by(TopologyNode.node_key)
                ).all()
            )
            edges = list(
                session.scalars(
                    select(TopologyEdge)
                    .where(TopologyEdge.snapshot_id == snapshot.id)
                    .order_by(TopologyEdge.source_node_key, TopologyEdge.target_node_key)
                ).all()
            )
        return TopologyPlanningContext(
            device_ip=device_ip,
            device=device,
            snapshot=snapshot,
            nodes=nodes,
            edges=edges,
            manual_nodes=list(session.scalars(select(ManualTopologyNode)).all()),
            manual_edges=list(session.scalars(select(ManualTopologyEdge)).all()),
            manual_notes=list(session.scalars(select(ManualTopologyNote)).all()),
            known_devices=list(
                session.scalars(
                    select(Device)
                    .options(selectinload(Device.ports), selectinload(Device.facts), selectinload(Device.observations))
                    .order_by(Device.ip_address)
                ).all()
            ),
        )


def analyze_plan_topology_risk(plan: ChangePlan) -> list[DiagnosticFinding]:
    if plan.device is None:
        return []
    findings: list[DiagnosticFinding] = []
    context = get_topology_context_for_device(plan.device.ip_address)
    findings.extend(_missing_topology_findings(context))

    if plan.plan_type == "mikrotik_dhcp_server":
        details = _parse_mikrotik_dhcp_plan(plan.proposed_commands)
        if details:
            findings.extend(analyze_dhcp_pool_overlap(details["network"], details["pool_range"]))
            findings.extend(analyze_interface_role(plan.device.ip_address, details["interface"]))
            findings.extend(_manual_findings(context, details["interface"], action="dhcp"))
            findings.extend(_gateway_topology_warning(context, details["network"], details["gateway"]))
    elif plan.plan_type == "mikrotik_address":
        interface = _parse_mikrotik_address_interface(plan.proposed_commands)
        findings.extend(analyze_interface_role(plan.device.ip_address, interface))
        findings.extend(_manual_findings(context, interface, action="address"))
    elif plan.plan_type in {"cisco_access_port", "cisco_interface_description"}:
        interface = _parse_cisco_interface(plan.proposed_commands)
        findings.extend(_manual_findings(context, interface, action=plan.plan_type))
        if plan.plan_type == "cisco_access_port":
            findings.extend(analyze_interface_role(plan.device.ip_address, interface))
    elif plan.plan_type == "vlan":
        ports = _parse_cisco_interface_range(plan.proposed_commands)
        findings.extend(_manual_findings(context, ports, action="vlan"))
    return findings


def analyze_dhcp_pool_overlap(network: str, pool_range: str) -> list[DiagnosticFinding]:
    findings: list[DiagnosticFinding] = []
    try:
        pool_start_raw, pool_end_raw = pool_range.split("-", 1)
        network_obj = ipaddress.ip_network(network, strict=True)
        pool_start = ipaddress.ip_address(pool_start_raw.strip())
        pool_end = ipaddress.ip_address(pool_end_raw.strip())
    except ValueError:
        return [
            DiagnosticFinding(
                severity="medium",
                title="DHCP pool overlap could not be checked",
                detail="The planned DHCP network or pool range could not be parsed for topology-aware analysis.",
            )
        ]
    init_db()
    with get_session() as session:
        devices = list(session.scalars(select(Device).order_by(Device.ip_address)).all())
    for device in devices:
        try:
            ip = ipaddress.ip_address(device.ip_address)
        except ValueError:
            continue
        if ip.version == 4 and ip in network_obj and int(pool_start) <= int(ip) <= int(pool_end):
            device_text = f"{device.vendor_guess} {device.device_type_guess}".lower()
            infra = any(term in device_text for term in ("router", "switch", "gateway", "mikrotik", "cisco"))
            findings.append(
                DiagnosticFinding(
                    severity="high" if infra else "medium",
                    title="DHCP pool overlaps known infrastructure IP" if infra else "DHCP pool overlaps known device IP",
                    detail=f"Planned DHCP pool `{pool_range}` includes known device `{device.ip_address}`.",
                    evidence=[f"{device.ip_address}: {device.vendor_guess} / {device.device_type_guess}"],
                    recommendation="Adjust the pool range or reserve known static/infrastructure addresses before approval.",
                )
            )
    return findings


def analyze_interface_role(device_ip: str, interface: str | None) -> list[DiagnosticFinding]:
    if not interface:
        return []
    lowered = interface.lower()
    findings: list[DiagnosticFinding] = []
    if any(term == lowered or term in lowered for term in UPLINK_TERMS):
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="Interface may be uplink/WAN",
                detail=f"Interface `{interface}` matches an uplink/WAN naming heuristic.",
                evidence=[f"Device: {device_ip}", f"Interface: {interface}"],
                recommendation="Verify this interface is not WAN/uplink/core before using it for DHCP or access changes.",
            )
        )
    elif not any(term == lowered or term in lowered for term in ACCESS_TERMS):
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="Interface role is not confirmed",
                detail=f"Topology has no client/access segment confirmation for interface `{interface}`.",
                recommendation="Use manual topology notes or read-only collection to confirm intended segment.",
            )
        )
    return findings


def _missing_topology_findings(context: TopologyPlanningContext) -> list[DiagnosticFinding]:
    findings: list[DiagnosticFinding] = []
    if context.snapshot is None:
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="No topology snapshot available",
                detail="No topology snapshot is available. Topology-aware analysis is limited.",
                recommendation="Run `python main.py topology build`.",
            )
        )
    if not context.manual_nodes and not context.manual_edges and not context.manual_notes:
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="No manual topology confirmation",
                detail="No manual topology confirmation exists for this device or segment.",
                recommendation="Add manual topology notes for uplinks, access ports, and critical segments when known.",
            )
        )
    return findings


def _manual_findings(context: TopologyPlanningContext, interface: str | None, action: str) -> list[DiagnosticFinding]:
    findings: list[DiagnosticFinding] = []
    haystacks: list[tuple[str, str]] = []
    device_keys = context.device_node_keys
    for node in context.manual_nodes:
        if node.node_key in device_keys or node.ip_address == context.device_ip:
            haystacks.append((f"manual node {node.node_key}", " ".join(part for part in (node.label, node.node_type, node.notes or "") if part)))
    for edge in context.manual_edges:
        if edge.source_node_key in device_keys or edge.target_node_key in device_keys:
            haystacks.append((f"manual edge {edge.source_node_key}->{edge.target_node_key}", " ".join(part for part in (edge.relation_type, edge.label or "", edge.notes or "") if part)))
    for note in context.manual_notes:
        target = note.target_key or ""
        if note.target_type == "topology" or target in device_keys or context.device_ip in target:
            haystacks.append((f"manual note {note.id}", note.note))

    if interface:
        for note in context.manual_notes:
            if interface.lower() in f"{note.target_key or ''} {note.note}".lower():
                haystacks.append((f"manual note {note.id}", note.note))
        for edge in context.manual_edges:
            text = f"{edge.source_node_key} {edge.target_node_key} {edge.label or ''} {edge.notes or ''}"
            if interface.lower() in text.lower():
                haystacks.append((f"manual edge {edge.source_node_key}->{edge.target_node_key}", text))

    seen: set[tuple[str, str]] = set()
    for source, text in haystacks:
        text = text.strip()
        if not text or (source, text) in seen:
            continue
        seen.add((source, text))
        lowered = text.lower()
        if any(term in lowered for term in DO_NOT_MODIFY_TERMS):
            findings.append(
                DiagnosticFinding(
                    severity="high",
                    title="Manual topology note blocks change",
                    detail="Manual topology evidence says this target should not be modified.",
                    evidence=[f"{source}: {text}"],
                    recommendation="Review or update the manual topology note before approving/preflighting this plan.",
                )
            )
        elif any(term in lowered for term in INFRA_TERMS):
            findings.append(
                DiagnosticFinding(
                    severity="medium",
                    title="Manual topology indicates infrastructure link",
                    detail="Interface or device may be an uplink/core/infrastructure connection based on manual topology evidence.",
                    evidence=[f"{source}: {text}", f"Action: {action}"],
                    recommendation="Verify this is not an uplink or downstream infrastructure link before proceeding.",
                )
            )
        else:
            findings.append(
                DiagnosticFinding(
                    severity="info",
                    title="Manual topology note found",
                    detail="Manual topology evidence exists for this target.",
                    evidence=[f"{source}: {text}"],
                )
            )
    return findings


def _gateway_topology_warning(context: TopologyPlanningContext, network: str, gateway: str) -> list[DiagnosticFinding]:
    try:
        gateway_ip = ipaddress.ip_address(gateway)
        network_obj = ipaddress.ip_network(network)
    except ValueError:
        return []
    if gateway_ip not in network_obj:
        return [
            DiagnosticFinding(
                severity="medium",
                title="Gateway is outside DHCP network",
                detail=f"Gateway `{gateway}` is not inside `{network}`.",
            )
        ]
    for device in context.known_devices:
        text = f"{device.vendor_guess} {device.device_type_guess}".lower()
        if device.ip_address != gateway and any(term in text for term in ("gateway", "router")):
            try:
                ip = ipaddress.ip_address(device.ip_address)
            except ValueError:
                continue
            if ip in network_obj:
                return [
                    DiagnosticFinding(
                        severity="medium",
                        title="Another gateway/router is known in target subnet",
                        detail="Inventory suggests another router/gateway exists in the planned DHCP network.",
                        evidence=[f"{device.ip_address}: {device.vendor_guess} / {device.device_type_guess}"],
                    )
                ]
    return []


def _parse_mikrotik_dhcp_plan(commands: str) -> dict[str, str] | None:
    pool = re.search(r"^/ip pool add name=([A-Za-z0-9_.-]+) ranges=([0-9.]+-[0-9.]+)$", commands, re.MULTILINE)
    server = re.search(r"^/ip dhcp-server add name=([A-Za-z0-9_.-]+) interface=([A-Za-z0-9_.\-/]+) address-pool=([A-Za-z0-9_.-]+) disabled=no", commands, re.MULTILINE)
    network = re.search(r"^/ip dhcp-server network add address=([0-9.]+/\d{1,2}) gateway=([0-9.]+)", commands, re.MULTILINE)
    if not pool or not server or not network:
        return None
    return {
        "pool_name": pool.group(1),
        "pool_range": pool.group(2),
        "name": server.group(1),
        "interface": server.group(2),
        "network": network.group(1),
        "gateway": network.group(2),
    }


def _parse_mikrotik_address_interface(commands: str) -> str | None:
    match = re.search(r"^/ip address add address=[0-9.]+/\d{1,2} interface=([A-Za-z0-9_.\-/]+)", commands, re.MULTILINE)
    return match.group(1) if match else None


def _parse_cisco_interface(commands: str) -> str | None:
    match = re.search(r"^interface\s+(.+)$", commands, re.MULTILINE)
    return match.group(1).strip() if match else None


def _parse_cisco_interface_range(commands: str) -> str | None:
    match = re.search(r"^interface range\s+(.+)$", commands, re.MULTILINE)
    return match.group(1).strip() if match else None
