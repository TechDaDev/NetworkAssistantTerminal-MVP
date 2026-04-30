from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app.llm_policy import LLMSafetyError
from app.services.command_router import route_local_command
from app.services.config_planner import ConfigPlanError, create_cisco_access_port_plan, create_cisco_description_plan, create_mikrotik_address_plan, create_mikrotik_dhcp_plan, create_vlan_plan, get_change_plan, list_change_plans
from app.services.config_planner import approve_change_plan, archive_change_plan, reject_change_plan, review_change_plan
from app.services.config_planner import run_preflight
from app.services.config_executor import ConfigExecutionError, execute_change_plan, get_execution_history
from app.services.config_executor import rollback_change_plan, save_plan_config, verify_change_plan
from app.services.config_snapshot import (
    ConfigSnapshotError,
    capture_manual_snapshot,
    generate_restore_guidance,
    list_snapshots,
    render_snapshot_export,
    show_snapshot,
)
from app.services.diagnostics import (
    DiagnosticError,
    diagnose_connectivity,
    diagnose_device,
    diagnose_management_ports,
    diagnose_network,
)
from app.services.doc_fetcher import DocFetchError, save_fetched_document_as_knowledge, search_official_docs
from app.services.inventory import get_latest_scan_report, list_devices
from app.services.knowledge import (
    KnowledgeError,
    add_knowledge,
    delete_knowledge,
    get_knowledge,
    list_knowledge,
    search_knowledge,
)
from app.services.manual_topology import (
    ManualTopologyError,
    add_manual_edge,
    add_manual_node,
    add_manual_note,
    delete_manual_edge,
    delete_manual_node,
    delete_manual_note,
    list_manual_edges,
    list_manual_nodes,
    list_manual_notes,
)
from app.services.llm_planner import LLMPlanner, LLMPlannerError
from app.services.network_detection import NetworkDetectionError
from app.services.nmap_tool import (
    get_nmap_version,
    is_nmap_available,
    run_nmap_scan,
    save_nmap_results,
)
from app.safety import UnsafeNetworkError
from app.services.serializers import device_to_dict, diagnostic_to_dict, scan_run_to_dict
from app.services.serializers import (
    change_plan_to_dict,
    config_snapshot_to_dict,
    execution_log_to_dict,
    knowledge_search_result_to_dict,
    knowledge_to_dict,
    manual_topology_edge_to_dict,
    manual_topology_node_to_dict,
    manual_topology_note_to_dict,
    topology_edge_to_dict,
    topology_node_to_dict,
    topology_snapshot_to_dict,
)
from app.services.topology import (
    build_topology_snapshot,
    explain_topology,
    export_topology_json,
    export_topology_mermaid,
    get_latest_topology,
    get_topology,
    rebuild_topology_with_manual,
)
from app.services.topology_exporter import (
    TopologyExportError,
    render_topology_html,
    render_topology_json,
    render_topology_markdown,
    render_topology_report,
)
from app.services.topology_awareness import analyze_plan_topology_risk


api = FastAPI(title="Network Assistant Local API", version="0.14.0")


def _nmap_result_to_dict(result) -> dict:
    return {
        "target": result.target,
        "profile": result.profile,
        "live_hosts_count": result.live_hosts_count,
        "devices": [device.model_dump(mode="json") for device in result.devices],
    }


class CommandRequest(BaseModel):
    text: str


class AskRequest(BaseModel):
    question: str


class DeviceRequest(BaseModel):
    ip: str


class ConnectivityRequest(BaseModel):
    target_ip: str


class NmapScanLocalRequest(BaseModel):
    profile: str = "common-ports"


class NmapScanTargetRequest(BaseModel):
    target: str
    profile: str = "common-ports"


class VlanPlanRequest(BaseModel):
    device: str
    vlan_id: int
    name: str
    ports: str | None = None


class MikroTikAddressPlanRequest(BaseModel):
    device: str
    interface: str
    address: str
    comment: str | None = None


class MikroTikDhcpPlanRequest(BaseModel):
    device: str
    name: str
    interface: str
    network: str
    gateway: str
    pool_name: str
    pool_range: str
    dns: str | None = None
    comment: str | None = None


class CiscoDescriptionPlanRequest(BaseModel):
    device: str
    interface: str
    description: str


class CiscoAccessPortPlanRequest(BaseModel):
    device: str
    interface: str
    vlan_id: int
    description: str | None = None


class PlanActionRequest(BaseModel):
    note: str | None = None


class PlanExecutionRequest(BaseModel):
    confirmation: str | None = None


class SnapshotCaptureRequest(BaseModel):
    plan_id: int
    snapshot_type: str = "manual"


class KnowledgeRequest(BaseModel):
    title: str
    content: str
    vendor: str | None = None
    model: str | None = None
    device_type: str | None = None
    doc_type: str = "vendor_note"
    tags: str = ""
    source_name: str | None = None
    is_trusted: bool = False
    source_type: str = "manual"
    source_url: str | None = None


class KnowledgeFetchUrlRequest(BaseModel):
    url: str
    vendor: str
    model: str | None = None
    doc_type: str = "vendor_note"
    tags: str = ""
    trusted: bool = False


class KnowledgeFetchDocsRequest(BaseModel):
    vendor: str
    model: str


class ManualTopologyNodeRequest(BaseModel):
    node_key: str
    label: str
    node_type: str
    ip_address: str | None = None
    mac_address: str | None = None
    vendor: str | None = None
    notes: str | None = None


class ManualTopologyEdgeRequest(BaseModel):
    source_node_key: str
    target_node_key: str
    relation_type: str = "manual"
    label: str | None = None
    confidence: str = "high"
    notes: str | None = None


class ManualTopologyNoteRequest(BaseModel):
    target_type: str
    target_key: str | None = None
    note: str


@api.get("/health")
def health() -> dict:
    return {"ok": True, "service": "network-assistant", "bind": "127.0.0.1"}


@api.get("/devices")
def devices() -> dict:
    items = [device_to_dict(device) for device in list_devices()]
    return {"ok": True, "devices": items}


@api.get("/knowledge")
def knowledge_list_endpoint() -> dict:
    return {"ok": True, "knowledge": [knowledge_to_dict(item) for item in list_knowledge()]}


@api.get("/knowledge/search")
def knowledge_search_endpoint(q: str) -> dict:
    return {"ok": True, "results": [knowledge_search_result_to_dict(result) for result in search_knowledge(q)]}


@api.post("/knowledge/fetch-url")
def knowledge_fetch_url_endpoint(request: KnowledgeFetchUrlRequest) -> dict:
    try:
        result = save_fetched_document_as_knowledge(
            url=request.url,
            vendor=request.vendor,
            model=request.model,
            doc_type=request.doc_type,
            trusted=request.trusted,
            tags=request.tags,
        )
    except DocFetchError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": True,
        "knowledge_id": result.knowledge_id,
        "title": result.document.title,
        "source_url": result.document.url,
        "official": result.document.official,
        "summarized": result.summarized,
        "warning": result.warning,
    }


@api.post("/knowledge/fetch-docs")
def knowledge_fetch_docs_endpoint(request: KnowledgeFetchDocsRequest) -> dict:
    try:
        results = search_official_docs(request.vendor, request.model)
    except DocFetchError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": bool(results),
        "results": [result.__dict__ for result in results],
        "message": "Automatic doc search is not configured yet. Use /knowledge/fetch-url with an official URL."
        if not results
        else "Candidate official documentation URLs.",
    }


@api.get("/knowledge/{knowledge_id}")
def knowledge_show_endpoint(knowledge_id: int) -> dict:
    item = get_knowledge(knowledge_id)
    if item is None:
        raise HTTPException(status_code=404, detail=f"Knowledge document {knowledge_id} not found.")
    return {"ok": True, "knowledge": knowledge_to_dict(item)}


@api.post("/knowledge")
def knowledge_add_endpoint(request: KnowledgeRequest) -> dict:
    try:
        item = add_knowledge(
            title=request.title,
            content=request.content,
            vendor=request.vendor,
            model=request.model,
            device_type=request.device_type,
            doc_type=request.doc_type,
            tags=request.tags,
            source_name=request.source_name,
            is_trusted=request.is_trusted,
            source_type=request.source_type,
            source_url=request.source_url,
        )
    except KnowledgeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "knowledge": knowledge_to_dict(item)}


@api.delete("/knowledge/{knowledge_id}")
def knowledge_delete_endpoint(knowledge_id: int) -> dict:
    deleted = delete_knowledge(knowledge_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Knowledge document {knowledge_id} not found.")
    return {"ok": True, "deleted": knowledge_id}


@api.get("/report/latest")
def report_latest() -> dict:
    report = get_latest_scan_report()
    scan = report.get("scan")
    return {
        "ok": bool(scan),
        "scan": scan_run_to_dict(scan),
        "devices": report.get("devices", []),
        "network_info": report.get("network_info", {}),
    }


@api.post("/topology/build")
def topology_build_endpoint() -> dict:
    result = build_topology_snapshot()
    return {"ok": True, "snapshot": topology_snapshot_to_dict(result.snapshot), "warnings": result.warnings}


@api.post("/topology/rebuild-with-manual")
def topology_rebuild_with_manual_endpoint() -> dict:
    result = rebuild_topology_with_manual()
    return {"ok": True, "snapshot": topology_snapshot_to_dict(result.snapshot), "warnings": result.warnings}


@api.get("/topology/manual/nodes")
def topology_manual_nodes_list_endpoint() -> dict:
    return {"ok": True, "nodes": [manual_topology_node_to_dict(node) for node in list_manual_nodes()]}


@api.post("/topology/manual/nodes")
def topology_manual_node_add_endpoint(request: ManualTopologyNodeRequest) -> dict:
    try:
        result = add_manual_node(
            node_key=request.node_key,
            label=request.label,
            node_type=request.node_type,
            ip_address=request.ip_address,
            mac_address=request.mac_address,
            vendor=request.vendor,
            notes=request.notes,
        )
    except ManualTopologyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "message": result.message, "warnings": result.warnings, "node": manual_topology_node_to_dict(result.item)}


@api.delete("/topology/manual/nodes/{node_id}")
def topology_manual_node_delete_endpoint(node_id: int, confirm: bool = False) -> dict:
    try:
        result = delete_manual_node(node_id, confirm=confirm)
    except ManualTopologyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "message": result.message}


@api.get("/topology/manual/edges")
def topology_manual_edges_list_endpoint() -> dict:
    return {"ok": True, "edges": [manual_topology_edge_to_dict(edge) for edge in list_manual_edges()]}


@api.post("/topology/manual/edges")
def topology_manual_edge_add_endpoint(request: ManualTopologyEdgeRequest) -> dict:
    try:
        result = add_manual_edge(
            source_node_key=request.source_node_key,
            target_node_key=request.target_node_key,
            relation_type=request.relation_type,
            label=request.label,
            confidence=request.confidence,
            notes=request.notes,
        )
    except ManualTopologyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "message": result.message, "warnings": result.warnings, "edge": manual_topology_edge_to_dict(result.item)}


@api.delete("/topology/manual/edges/{edge_id}")
def topology_manual_edge_delete_endpoint(edge_id: int, confirm: bool = False) -> dict:
    try:
        result = delete_manual_edge(edge_id, confirm=confirm)
    except ManualTopologyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "message": result.message}


@api.get("/topology/manual/notes")
def topology_manual_notes_list_endpoint() -> dict:
    return {"ok": True, "notes": [manual_topology_note_to_dict(note) for note in list_manual_notes()]}


@api.post("/topology/manual/notes")
def topology_manual_note_add_endpoint(request: ManualTopologyNoteRequest) -> dict:
    try:
        result = add_manual_note(target_type=request.target_type, target_key=request.target_key, note=request.note)
    except ManualTopologyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "message": result.message, "warnings": result.warnings, "note": manual_topology_note_to_dict(result.item)}


@api.delete("/topology/manual/notes/{note_id}")
def topology_manual_note_delete_endpoint(note_id: int, confirm: bool = False) -> dict:
    try:
        result = delete_manual_note(note_id, confirm=confirm)
    except ManualTopologyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "message": result.message}


@api.get("/topology")
def topology_latest_endpoint() -> dict:
    result = get_latest_topology()
    if result is None:
        return {"ok": False, "message": "No topology snapshot exists."}
    return {
        "ok": True,
        "snapshot": topology_snapshot_to_dict(result.snapshot),
        "nodes": [topology_node_to_dict(node) for node in result.nodes],
        "edges": [topology_edge_to_dict(edge) for edge in result.edges],
    }


@api.get("/topology/export")
def topology_export_endpoint(format: str = "json") -> dict:
    if format == "json":
        return {"ok": True, "format": "json", "topology": export_topology_json()}
    if format == "mermaid":
        return {"ok": True, "format": "mermaid", "text": export_topology_mermaid()}
    raise HTTPException(status_code=400, detail="Unsupported format. Use json or mermaid.")


@api.get("/topology/export-file")
def topology_export_file_content_endpoint(format: str = "json", snapshot_id: int | None = None, offline: bool = False) -> dict:
    try:
        if format == "mermaid":
            return {"ok": True, "format": "mermaid", "content": render_topology_markdown(snapshot_id)}
        if format == "json":
            return {"ok": True, "format": "json", "content": render_topology_json(snapshot_id)}
        if format == "html":
            return {"ok": True, "format": "html", "content": render_topology_html(snapshot_id, offline=offline)}
    except TopologyExportError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    raise HTTPException(status_code=400, detail="Unsupported format. Use mermaid, json, or html.")


@api.get("/topology/report")
def topology_report_endpoint(snapshot_id: int | None = None) -> dict:
    try:
        return {"ok": True, "format": "markdown", "content": render_topology_report(snapshot_id)}
    except TopologyExportError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@api.get("/topology/explain")
def topology_explain_endpoint() -> dict:
    return {"ok": True, "diagnostic": diagnostic_to_dict(explain_topology())}


@api.get("/topology/risk-check/{plan_id}")
def topology_risk_check_endpoint(plan_id: int) -> dict:
    plan = get_change_plan(plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail=f"Change plan {plan_id} not found.")
    return {
        "ok": True,
        "plan_id": plan_id,
        "findings": [finding.model_dump(mode="json") for finding in analyze_plan_topology_risk(plan)],
    }


@api.get("/topology/{snapshot_id}")
def topology_show_endpoint(snapshot_id: int) -> dict:
    result = get_topology(snapshot_id)
    return {
        "ok": True,
        "snapshot": topology_snapshot_to_dict(result.snapshot),
        "nodes": [topology_node_to_dict(node) for node in result.nodes],
        "edges": [topology_edge_to_dict(edge) for edge in result.edges],
    }


@api.post("/command")
def command(request: CommandRequest) -> dict:
    try:
        return route_local_command(request.text).to_dict()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@api.post("/ask")
def ask(request: AskRequest) -> dict:
    try:
        answer = LLMPlanner().answer_question(request.question)
    except (LLMPlannerError, LLMSafetyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "answer": answer}


@api.post("/diagnose/network")
def diagnose_network_endpoint() -> dict:
    try:
        return {"ok": True, "diagnostic": diagnostic_to_dict(diagnose_network())}
    except NetworkDetectionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@api.post("/diagnose/device")
def diagnose_device_endpoint(request: DeviceRequest) -> dict:
    try:
        return {"ok": True, "diagnostic": diagnostic_to_dict(diagnose_device(request.ip))}
    except DiagnosticError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@api.post("/diagnose/management-ports")
def diagnose_management_ports_endpoint() -> dict:
    return {"ok": True, "diagnostic": diagnostic_to_dict(diagnose_management_ports())}


@api.post("/diagnose/connectivity")
def diagnose_connectivity_endpoint(request: ConnectivityRequest) -> dict:
    try:
        return {"ok": True, "diagnostic": diagnostic_to_dict(diagnose_connectivity(request.target_ip))}
    except (DiagnosticError, NetworkDetectionError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@api.get("/nmap/check")
def nmap_check_endpoint() -> dict:
    return {"ok": True, "available": is_nmap_available(), "version": get_nmap_version()}


@api.post("/nmap/scan-local")
def nmap_scan_local_endpoint(request: NmapScanLocalRequest) -> dict:
    try:
        from app.services.network_detection import detect_local_network

        result = run_nmap_scan(detect_local_network().cidr, request.profile)
        save_nmap_results(result)
    except (UnsafeNetworkError, NetworkDetectionError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "scan": _nmap_result_to_dict(result)}


@api.post("/nmap/scan-host")
def nmap_scan_host_endpoint(request: NmapScanTargetRequest) -> dict:
    try:
        result = run_nmap_scan(request.target, request.profile)
        save_nmap_results(result)
    except (UnsafeNetworkError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "scan": _nmap_result_to_dict(result)}


@api.post("/nmap/scan-device")
def nmap_scan_device_endpoint(request: NmapScanTargetRequest) -> dict:
    try:
        if not any(device.ip_address == request.target for device in list_devices()):
            raise HTTPException(status_code=404, detail=f"Device {request.target} not found in inventory.")
        result = run_nmap_scan(request.target, request.profile)
        save_nmap_results(result)
    except HTTPException:
        raise
    except (UnsafeNetworkError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "scan": _nmap_result_to_dict(result)}


@api.post("/plan/vlan")
def plan_vlan_endpoint(request: VlanPlanRequest) -> dict:
    try:
        result = create_vlan_plan(
            device_ip=request.device,
            vlan_id=request.vlan_id,
            name=request.name,
            ports=request.ports,
        )
    except ConfigPlanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "plan": change_plan_to_dict(result.plan)}


@api.post("/plan/mikrotik/address")
def plan_mikrotik_address_endpoint(request: MikroTikAddressPlanRequest) -> dict:
    try:
        result = create_mikrotik_address_plan(
            device_ip=request.device,
            interface=request.interface,
            address=request.address,
            comment=request.comment,
        )
    except ConfigPlanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": True,
        "plan": change_plan_to_dict(result.plan),
        "warning": "PLAN ONLY -- NO COMMANDS EXECUTED. MIKROTIK EXECUTION IS NOT SUPPORTED YET.",
    }


@api.post("/plan/mikrotik/dhcp")
def plan_mikrotik_dhcp_endpoint(request: MikroTikDhcpPlanRequest) -> dict:
    try:
        result = create_mikrotik_dhcp_plan(
            device_ip=request.device,
            name=request.name,
            interface=request.interface,
            network=request.network,
            gateway=request.gateway,
            pool_name=request.pool_name,
            pool_range=request.pool_range,
            dns=request.dns,
            comment=request.comment,
        )
    except ConfigPlanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": True,
        "plan": change_plan_to_dict(result.plan),
        "warning": "PLAN ONLY -- NO COMMANDS EXECUTED. MIKROTIK DHCP EXECUTION IS NOT SUPPORTED YET.",
    }


@api.post("/plan/cisco/description")
def plan_cisco_description_endpoint(request: CiscoDescriptionPlanRequest) -> dict:
    try:
        result = create_cisco_description_plan(
            device_ip=request.device,
            interface=request.interface,
            description=request.description,
        )
    except ConfigPlanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": True,
        "plan": change_plan_to_dict(result.plan),
        "warning": "PLAN ONLY -- NO COMMANDS EXECUTED. CISCO INTERFACE EXECUTION IS NOT SUPPORTED YET.",
    }


@api.post("/plan/cisco/access-port")
def plan_cisco_access_port_endpoint(request: CiscoAccessPortPlanRequest) -> dict:
    try:
        result = create_cisco_access_port_plan(
            device_ip=request.device,
            interface=request.interface,
            vlan_id=request.vlan_id,
            description=request.description,
        )
    except ConfigPlanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": True,
        "plan": change_plan_to_dict(result.plan),
        "warning": "PLAN ONLY -- NO COMMANDS EXECUTED. CISCO INTERFACE EXECUTION IS NOT SUPPORTED YET.",
    }


@api.get("/plan")
def plan_list_endpoint() -> dict:
    return {"ok": True, "plans": [change_plan_to_dict(plan) for plan in list_change_plans()]}


@api.get("/plan/{plan_id}")
def plan_show_endpoint(plan_id: int) -> dict:
    plan = get_change_plan(plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail=f"Change plan {plan_id} not found.")
    return {"ok": True, "plan": change_plan_to_dict(plan)}


@api.post("/plan/{plan_id}/review")
def plan_review_endpoint(plan_id: int, request: PlanActionRequest | None = None) -> dict:
    try:
        plan = review_change_plan(plan_id, note=request.note if request else None)
    except ConfigPlanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "plan": change_plan_to_dict(plan)}


@api.post("/plan/{plan_id}/approve")
def plan_approve_endpoint(plan_id: int, request: PlanActionRequest | None = None) -> dict:
    try:
        plan = approve_change_plan(plan_id, note=request.note if request else None)
    except ConfigPlanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "plan": change_plan_to_dict(plan), "warning": "APPROVAL ONLY -- NO COMMANDS EXECUTED"}


@api.post("/plan/{plan_id}/reject")
def plan_reject_endpoint(plan_id: int, request: PlanActionRequest | None = None) -> dict:
    try:
        plan = reject_change_plan(plan_id, note=request.note if request else None)
    except ConfigPlanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "plan": change_plan_to_dict(plan)}


@api.post("/plan/{plan_id}/archive")
def plan_archive_endpoint(plan_id: int, request: PlanActionRequest | None = None) -> dict:
    try:
        plan = archive_change_plan(plan_id, note=request.note if request else None)
    except ConfigPlanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "plan": change_plan_to_dict(plan)}


@api.post("/plan/{plan_id}/preflight")
def plan_preflight_endpoint(plan_id: int, refresh: bool = False) -> dict:
    try:
        result = run_preflight(plan_id, refresh=refresh)
    except ConfigPlanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": True,
        "plan": change_plan_to_dict(result.plan),
        "findings": [finding.model_dump(mode="json") for finding in result.findings],
        "warning": "PREFLIGHT ONLY -- NO CONFIGURATION EXECUTED",
    }


@api.get("/plan/{plan_id}/execution-history")
def plan_execution_history_endpoint(plan_id: int) -> dict:
    return {"ok": True, "logs": [execution_log_to_dict(log) for log in get_execution_history(plan_id)]}


@api.post("/plan/{plan_id}/execute")
def plan_execute_endpoint(plan_id: int, request: PlanExecutionRequest | None = None, dry_run: bool = False) -> dict:
    try:
        result = execute_change_plan(
            plan_id,
            dry_run=dry_run,
            confirmation=request.confirmation if request else None,
        )
    except ConfigExecutionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": True,
        "dry_run": result.dry_run,
        "message": result.message,
        "plan": change_plan_to_dict(result.plan),
        "log": execution_log_to_dict(result.log) if result.log else None,
        "warning": "Configuration execution endpoint. Real execution requires exact confirmation.",
    }


@api.post("/plan/{plan_id}/verify")
def plan_verify_endpoint(plan_id: int) -> dict:
    try:
        result = verify_change_plan(plan_id)
    except ConfigExecutionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": True,
        "message": result.message,
        "plan": change_plan_to_dict(result.plan),
        "log": execution_log_to_dict(result.log) if result.log else None,
        "warning": "VERIFY ONLY -- READ-ONLY COMMANDS EXECUTED",
    }


@api.post("/plan/{plan_id}/save")
def plan_save_endpoint(plan_id: int, request: PlanExecutionRequest | None = None) -> dict:
    try:
        result = save_plan_config(plan_id, confirmation=request.confirmation if request else None)
    except ConfigExecutionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": True,
        "message": result.message,
        "plan": change_plan_to_dict(result.plan),
        "log": execution_log_to_dict(result.log) if result.log else None,
        "warning": "SAVE OPERATION -- EXACT CONFIRMATION REQUIRED",
    }


@api.post("/plan/{plan_id}/rollback")
def plan_rollback_endpoint(plan_id: int, request: PlanExecutionRequest | None = None) -> dict:
    try:
        result = rollback_change_plan(plan_id, confirmation=request.confirmation if request else None)
    except ConfigExecutionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": True,
        "message": result.message,
        "plan": change_plan_to_dict(result.plan),
        "log": execution_log_to_dict(result.log) if result.log else None,
        "warning": "ROLLBACK OPERATION -- EXACT CONFIRMATION REQUIRED",
    }


@api.get("/snapshots")
def snapshots_endpoint(device: str | None = None, plan_id: int | None = None) -> dict:
    return {
        "ok": True,
        "snapshots": [config_snapshot_to_dict(snapshot) for snapshot in list_snapshots(device_ip=device, plan_id=plan_id)],
    }


@api.get("/snapshots/{snapshot_id}")
def snapshot_show_endpoint(snapshot_id: int) -> dict:
    snapshot = show_snapshot(snapshot_id)
    if snapshot is None:
        raise HTTPException(status_code=404, detail="Snapshot not found.")
    data = config_snapshot_to_dict(snapshot)
    data["content"] = snapshot.content
    return {"ok": True, "snapshot": data}


@api.get("/snapshots/{snapshot_id}/export")
def snapshot_export_endpoint(snapshot_id: int, format: str) -> dict:
    try:
        content = render_snapshot_export(snapshot_id, format)
    except ConfigSnapshotError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "snapshot_id": snapshot_id, "format": format, "content": content}


@api.get("/snapshots/{snapshot_id}/restore-guidance")
def snapshot_restore_guidance_endpoint(snapshot_id: int) -> dict:
    try:
        guidance = generate_restore_guidance(snapshot_id)
    except ConfigSnapshotError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": True,
        "guidance": {
            "snapshot_id": guidance.snapshot_id,
            "platform": guidance.platform,
            "title": guidance.title,
            "summary": guidance.summary,
            "warnings": guidance.warnings,
            "recommended_steps": guidance.recommended_steps,
            "rollback_commands": guidance.rollback_commands,
        },
    }


@api.post("/snapshots/capture")
def snapshot_capture_endpoint(request: SnapshotCaptureRequest) -> dict:
    if request.snapshot_type != "manual":
        raise HTTPException(status_code=400, detail="Only manual snapshot capture is supported through this endpoint.")
    try:
        snapshot = capture_manual_snapshot(request.plan_id)
    except ConfigSnapshotError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "snapshot": config_snapshot_to_dict(snapshot)}
