from __future__ import annotations

from datetime import datetime, timezone

from app.models import (
    ChangePlan,
    CommandRun,
    Device,
    DeviceConfigSnapshot,
    DeviceKnowledge,
    DevicePort,
    ExecutionLog,
    ManualTopologyEdge,
    ManualTopologyNode,
    ManualTopologyNote,
    ScanRun,
    TopologyEdge,
    TopologyNode,
    TopologySnapshot,
)
from app.services.knowledge import KnowledgeSearchResult
from app.services.custom_plan_generator import metadata_for_plan
from app.schemas import DiagnosticResult, ScanResult


def dt(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def sort_dt(value: datetime | None) -> datetime:
    if value is None:
        return datetime.min
    if value.tzinfo is not None:
        return value.replace(tzinfo=None)
    return value


def port_to_dict(port: DevicePort) -> dict:
    return {
        "port": port.port,
        "protocol": port.protocol,
        "service_guess": port.service_guess,
        "state": port.state,
        "last_seen": dt(port.last_seen),
    }


def command_run_to_dict(run: CommandRun) -> dict:
    output = run.output or ""
    error = run.error_message or ""
    return {
        "id": run.id,
        "command": run.command,
        "success": run.success,
        "started_at": dt(run.started_at),
        "finished_at": dt(run.finished_at),
        "output_preview": output[:800],
        "error_message": error[:800] if error else None,
    }


def device_to_dict(device: Device) -> dict:
    return {
        "id": device.id,
        "ip_address": device.ip_address,
        "hostname": device.hostname,
        "mac_address": device.mac_address,
        "vendor_guess": device.vendor_guess,
        "device_type_guess": device.device_type_guess,
        "confidence": device.confidence,
        "last_seen": dt(device.last_seen),
        "open_ports": [port_to_dict(port) for port in sorted(device.ports, key=lambda item: item.port)],
        "observations": [
            {
                "type": observation.observation_type,
                "value": observation.observation_value,
                "source": observation.source,
                "confidence": observation.confidence,
                "created_at": dt(observation.created_at),
            }
            for observation in sorted(device.observations, key=lambda item: item.created_at, reverse=True)
        ],
        "credentials": [
            {
                "connection_type": credential.connection_type,
                "username": credential.username,
                "platform_hint": credential.platform_hint,
                "port": credential.port,
                "status": credential.status,
                "last_success_at": dt(credential.last_success_at),
            }
            for credential in sorted(device.credentials, key=lambda item: item.updated_at, reverse=True)
        ],
        "recent_command_runs": [
            command_run_to_dict(run)
            for run in sorted(device.command_runs, key=lambda item: item.started_at, reverse=True)[:10]
        ],
    }


def scan_run_to_dict(scan: ScanRun | None) -> dict | None:
    if scan is None:
        return None
    return {
        "id": scan.id,
        "interface_name": scan.interface_name,
        "local_ip": scan.local_ip,
        "cidr": scan.cidr,
        "gateway_ip": scan.gateway_ip,
        "started_at": dt(scan.started_at),
        "finished_at": dt(scan.finished_at),
        "live_hosts_count": scan.live_hosts_count,
    }


def diagnostic_to_dict(result: DiagnosticResult) -> dict:
    return result.model_dump(mode="json")


def scan_result_to_dict(result: ScanResult) -> dict:
    return result.model_dump(mode="json")


def change_plan_to_dict(plan: ChangePlan) -> dict:
    latest_verification = _latest_log_status(plan, {"verified", "verification_failed"})
    latest_save = _latest_log_status(plan, {"save_success", "save_failed"})
    latest_execution = _latest_log_status(
        plan,
        {"success", "failed", "rolled_back", "rollback_failed", "manual_rollback_success", "manual_rollback_failed"},
    )
    return {
        "id": plan.id,
        "device_ip": plan.device.ip_address if plan.device else None,
        "plan_type": plan.plan_type,
        "title": plan.title,
        "description": plan.description,
        "risk_level": plan.risk_level,
        "status": plan.status,
        "proposed_commands": plan.proposed_commands,
        "rollback_commands": plan.rollback_commands,
        "validation_findings": plan.validation_findings,
        "custom_plan_metadata": metadata_for_plan(plan),
        "preflight_status": plan.preflight_status,
        "preflight_checked_at": dt(plan.preflight_checked_at),
        "preflight_summary": plan.preflight_summary,
        "latest_execution_status": latest_execution,
        "latest_verification_status": latest_verification,
        "config_saved": latest_save == "save_success" or plan.status == "saved",
        "rollback_available": bool((plan.rollback_commands or "").strip()),
        "approval_history": [
            {
                "action": log.action,
                "note": log.note,
                "created_at": dt(log.created_at),
            }
            for log in sorted(plan.approval_logs, key=lambda item: sort_dt(item.created_at))
        ],
        "created_at": dt(plan.created_at),
        "updated_at": dt(plan.updated_at),
    }


def _latest_log_status(plan: ChangePlan, statuses: set[str]) -> str | None:
    logs = [log for log in plan.execution_logs if log.status in statuses]
    if not logs:
        return None
    return max(logs, key=lambda item: sort_dt(item.started_at)).status


def execution_log_to_dict(log: ExecutionLog) -> dict:
    return {
        "id": log.id,
        "plan_id": log.plan_id,
        "device_ip": log.device.ip_address if log.device else None,
        "status": log.status,
        "started_at": dt(log.started_at),
        "finished_at": dt(log.finished_at),
        "pre_check_preview": (log.pre_check_output or "")[:800],
        "execution_preview": (log.execution_output or "")[:800],
        "post_check_preview": (log.post_check_output or "")[:800],
        "rollback_preview": (log.rollback_output or "")[:800],
        "error_message": log.error_message,
    }


def config_snapshot_to_dict(snapshot: DeviceConfigSnapshot) -> dict:
    return {
        "id": snapshot.id,
        "device_ip": snapshot.device.ip_address if snapshot.device else None,
        "device_id": snapshot.device_id,
        "plan_id": snapshot.plan_id,
        "execution_log_id": snapshot.execution_log_id,
        "snapshot_type": snapshot.snapshot_type,
        "platform": snapshot.platform,
        "created_at": dt(snapshot.created_at),
        "commands": _snapshot_commands(snapshot),
        "content_preview": (snapshot.content or "")[:1200],
    }


def _snapshot_commands(snapshot: DeviceConfigSnapshot) -> list[str]:
    try:
        import json

        data = json.loads(snapshot.command_outputs_json or "{}")
    except Exception:
        return []
    if isinstance(data, dict):
        return list(data.keys())
    return []


def knowledge_to_dict(item: DeviceKnowledge) -> dict:
    return {
        "id": item.id,
        "vendor": item.vendor,
        "model": item.model,
        "device_type": item.device_type,
        "doc_type": item.doc_type,
        "tags": item.tags,
        "title": item.title,
        "content": item.content,
        "source_type": item.source_type,
        "source_url": item.source_url,
        "source_name": item.source_name,
        "is_trusted": item.is_trusted,
        "last_used_at": dt(item.last_used_at),
        "created_at": dt(item.created_at),
        "updated_at": dt(item.updated_at),
    }


def knowledge_search_result_to_dict(result: KnowledgeSearchResult) -> dict:
    data = knowledge_to_dict(result.item)
    data["rank"] = result.rank
    data["preview"] = result.preview
    return data


def topology_snapshot_to_dict(snapshot: TopologySnapshot | None) -> dict | None:
    if snapshot is None:
        return None
    return {
        "id": snapshot.id,
        "title": snapshot.title,
        "source": snapshot.source,
        "created_at": dt(snapshot.created_at),
        "summary_json": snapshot.summary_json,
    }


def topology_node_to_dict(node: TopologyNode) -> dict:
    return {
        "id": node.id,
        "snapshot_id": node.snapshot_id,
        "device_id": node.device_id,
        "node_key": node.node_key,
        "ip_address": node.ip_address,
        "mac_address": node.mac_address,
        "label": node.label,
        "node_type": node.node_type,
        "vendor": node.vendor,
        "confidence": node.confidence,
        "evidence": node.evidence,
    }


def topology_edge_to_dict(edge: TopologyEdge) -> dict:
    return {
        "id": edge.id,
        "snapshot_id": edge.snapshot_id,
        "source_node_key": edge.source_node_key,
        "target_node_key": edge.target_node_key,
        "relation_type": edge.relation_type,
        "confidence": edge.confidence,
        "evidence_source": edge.evidence_source,
        "evidence": edge.evidence,
    }


def manual_topology_node_to_dict(node: ManualTopologyNode) -> dict:
    return {
        "id": node.id,
        "node_key": node.node_key,
        "label": node.label,
        "node_type": node.node_type,
        "ip_address": node.ip_address,
        "mac_address": node.mac_address,
        "vendor": node.vendor,
        "notes": node.notes,
        "created_at": dt(node.created_at),
        "updated_at": dt(node.updated_at),
    }


def manual_topology_edge_to_dict(edge: ManualTopologyEdge) -> dict:
    return {
        "id": edge.id,
        "source_node_key": edge.source_node_key,
        "target_node_key": edge.target_node_key,
        "relation_type": edge.relation_type,
        "label": edge.label,
        "confidence": edge.confidence,
        "notes": edge.notes,
        "created_at": dt(edge.created_at),
        "updated_at": dt(edge.updated_at),
    }


def manual_topology_note_to_dict(note: ManualTopologyNote) -> dict:
    return {
        "id": note.id,
        "target_type": note.target_type,
        "target_key": note.target_key,
        "note": note.note,
        "created_at": dt(note.created_at),
        "updated_at": dt(note.updated_at),
    }
