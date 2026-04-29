from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from sqlalchemy import select

from app.database import get_session, init_db
from app.models import ManualTopologyEdge, ManualTopologyNode, ManualTopologyNote


NODE_TYPES = {"local_host", "gateway", "router", "switch", "access_point", "server", "client", "unknown"}
RELATION_TYPES = {"default_gateway", "same_subnet", "cdp_neighbor", "lldp_neighbor", "arp_neighbor", "inferred", "manual"}
CONFIDENCE_LEVELS = {"low", "medium", "high"}
NOTE_TARGET_TYPES = {"node", "edge", "topology"}
SAFE_KEY_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


class ManualTopologyError(ValueError):
    pass


@dataclass
class ManualTopologyOperationResult:
    success: bool
    message: str
    warnings: list[str] = field(default_factory=list)
    item: ManualTopologyNode | ManualTopologyEdge | ManualTopologyNote | None = None


def add_manual_node(
    *,
    node_key: str,
    label: str,
    node_type: str,
    ip_address: str | None = None,
    mac_address: str | None = None,
    vendor: str | None = None,
    notes: str | None = None,
) -> ManualTopologyOperationResult:
    init_db()
    validate_node_key(node_key)
    validate_label(label)
    validate_node_type(node_type)
    validate_optional_ip(ip_address)
    validate_notes(notes)
    with get_session() as session:
        existing = session.scalar(select(ManualTopologyNode).where(ManualTopologyNode.node_key == node_key))
        if existing is not None:
            raise ManualTopologyError(f"Manual topology node `{node_key}` already exists.")
        node = ManualTopologyNode(
            node_key=node_key,
            label=label,
            node_type=node_type,
            ip_address=ip_address,
            mac_address=mac_address,
            vendor=vendor,
            notes=notes,
        )
        session.add(node)
        session.commit()
        session.refresh(node)
        return ManualTopologyOperationResult(True, f"Manual node `{node_key}` added.", item=node)


def list_manual_nodes() -> list[ManualTopologyNode]:
    init_db()
    with get_session() as session:
        return list(session.scalars(select(ManualTopologyNode).order_by(ManualTopologyNode.node_key)).all())


def delete_manual_node(node_id: int, *, confirm: bool = False) -> ManualTopologyOperationResult:
    _require_delete_confirmation(confirm)
    init_db()
    with get_session() as session:
        node = session.get(ManualTopologyNode, node_id)
        if node is None:
            raise ManualTopologyError(f"Manual topology node {node_id} not found.")
        key = node.node_key
        session.delete(node)
        session.commit()
        return ManualTopologyOperationResult(True, f"Manual node `{key}` deleted.")


def add_manual_edge(
    *,
    source_node_key: str,
    target_node_key: str,
    relation_type: str = "manual",
    label: str | None = None,
    confidence: str = "high",
    notes: str | None = None,
) -> ManualTopologyOperationResult:
    init_db()
    validate_node_key(source_node_key)
    validate_node_key(target_node_key)
    if source_node_key == target_node_key:
        raise ManualTopologyError("Manual topology edge source and target cannot be identical.")
    validate_relation_type(relation_type)
    validate_confidence(confidence)
    validate_label(label, required=False)
    validate_notes(notes)
    warnings = _missing_endpoint_warnings(source_node_key, target_node_key)
    with get_session() as session:
        edge = ManualTopologyEdge(
            source_node_key=source_node_key,
            target_node_key=target_node_key,
            relation_type=relation_type,
            label=label,
            confidence=confidence,
            notes=notes,
        )
        session.add(edge)
        session.commit()
        session.refresh(edge)
        return ManualTopologyOperationResult(True, f"Manual edge `{source_node_key}` -> `{target_node_key}` added.", warnings, edge)


def list_manual_edges() -> list[ManualTopologyEdge]:
    init_db()
    with get_session() as session:
        return list(
            session.scalars(
                select(ManualTopologyEdge).order_by(ManualTopologyEdge.source_node_key, ManualTopologyEdge.target_node_key)
            ).all()
        )


def delete_manual_edge(edge_id: int, *, confirm: bool = False) -> ManualTopologyOperationResult:
    _require_delete_confirmation(confirm)
    init_db()
    with get_session() as session:
        edge = session.get(ManualTopologyEdge, edge_id)
        if edge is None:
            raise ManualTopologyError(f"Manual topology edge {edge_id} not found.")
        label = f"{edge.source_node_key} -> {edge.target_node_key}"
        session.delete(edge)
        session.commit()
        return ManualTopologyOperationResult(True, f"Manual edge `{label}` deleted.")


def add_manual_note(*, target_type: str, target_key: str | None, note: str) -> ManualTopologyOperationResult:
    init_db()
    validate_note_target_type(target_type)
    if target_key:
        if target_type == "edge" and "->" in target_key:
            source, target = target_key.split("->", 1)
            validate_node_key(source)
            validate_node_key(target)
        else:
            validate_node_key(target_key)
    validate_notes(note, required=True)
    with get_session() as session:
        item = ManualTopologyNote(target_type=target_type, target_key=target_key, note=note)
        session.add(item)
        session.commit()
        session.refresh(item)
        return ManualTopologyOperationResult(True, "Manual topology note added.", item=item)


def list_manual_notes() -> list[ManualTopologyNote]:
    init_db()
    with get_session() as session:
        return list(session.scalars(select(ManualTopologyNote).order_by(ManualTopologyNote.created_at.desc())).all())


def delete_manual_note(note_id: int, *, confirm: bool = False) -> ManualTopologyOperationResult:
    _require_delete_confirmation(confirm)
    init_db()
    with get_session() as session:
        note = session.get(ManualTopologyNote, note_id)
        if note is None:
            raise ManualTopologyError(f"Manual topology note {note_id} not found.")
        session.delete(note)
        session.commit()
        return ManualTopologyOperationResult(True, f"Manual note {note_id} deleted.")


def validate_node_key(value: str) -> None:
    if not value or not SAFE_KEY_RE.fullmatch(value):
        raise ManualTopologyError("Node keys may contain only letters, numbers, dash, underscore, and dot.")


def validate_label(value: str | None, *, required: bool = True) -> None:
    if required and not value:
        raise ManualTopologyError("Label is required.")
    if value and len(value) > 80:
        raise ManualTopologyError("Labels must be 80 characters or fewer.")


def validate_notes(value: str | None, *, required: bool = False) -> None:
    if required and not value:
        raise ManualTopologyError("Note text is required.")
    if value and len(value) > 1000:
        raise ManualTopologyError("Notes must be 1000 characters or fewer.")


def validate_node_type(value: str) -> None:
    if value not in NODE_TYPES:
        raise ManualTopologyError(f"Unsupported node type `{value}`. Use one of: {', '.join(sorted(NODE_TYPES))}.")


def validate_relation_type(value: str) -> None:
    if value not in RELATION_TYPES:
        raise ManualTopologyError(f"Unsupported relation type `{value}`. Use one of: {', '.join(sorted(RELATION_TYPES))}.")


def validate_confidence(value: str) -> None:
    if value not in CONFIDENCE_LEVELS:
        raise ManualTopologyError("Confidence must be one of: low, medium, high.")


def validate_note_target_type(value: str) -> None:
    if value not in NOTE_TARGET_TYPES:
        raise ManualTopologyError("Note target type must be one of: node, edge, topology.")


def validate_optional_ip(value: str | None) -> None:
    if not value:
        return
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ManualTopologyError(f"Invalid IP address `{value}`.") from exc


def _require_delete_confirmation(confirm: bool) -> None:
    if not confirm:
        raise ManualTopologyError("Manual topology delete requires explicit confirmation.")


def _missing_endpoint_warnings(source_node_key: str, target_node_key: str) -> list[str]:
    from app.services.topology import get_latest_topology

    existing = {node.node_key for node in list_manual_nodes()}
    latest = get_latest_topology()
    if latest is not None:
        existing.update(node.node_key for node in latest.nodes)
    warnings: list[str] = []
    for key in (source_node_key, target_node_key):
        if key not in existing:
            warnings.append(f"Manual edge endpoint `{key}` is not present in latest topology or manual nodes.")
    return warnings
