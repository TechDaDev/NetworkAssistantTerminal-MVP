from __future__ import annotations

import json
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from types import SimpleNamespace

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.database import get_session, init_db
from app.models import ApprovalLog, ChangePlan, CommandRun, Device
from app.schemas import DiagnosticFinding
from app.services.device_connection import DeviceConnectionError, run_readonly_command, run_readonly_profile_collection
from app.services.custom_command_validator import (
    classify_commands,
    has_blocked_command,
    has_double_confirmation,
    validate_precheck_command,
    validate_verification_command,
)
from app.services.custom_plan_generator import metadata_for_plan


class ConfigPlanError(ValueError):
    """Raised when a configuration plan request is invalid or unsafe."""


@dataclass
class ChangePlanResult:
    plan: ChangePlan
    findings: list[DiagnosticFinding]


@dataclass(frozen=True)
class MikroTikDhcpPlanParts:
    name: str
    interface: str
    network: str
    gateway: str
    pool_name: str
    pool_range: str
    dns: str | None
    comment: str | None


SAFE_VLAN_NAME = re.compile(r"^[A-Za-z0-9 _-]{1,32}$")
UNSAFE_PORT_CHARS = re.compile(r"[;|&`\n\r]")
PORT_FORMAT = re.compile(r"^[A-Za-z]+[A-Za-z0-9/ .,-]+$")
CISCO_INTERFACE = re.compile(
    r"^(?:Gi|GigabitEthernet|Fa|FastEthernet|Te|TenGigabitEthernet|Eth|Ethernet)\d+(?:/\d+){1,3}$",
    re.IGNORECASE,
)
CISCO_DESCRIPTION_UNSAFE = re.compile(r"[\n\r;|&`$\x00-\x1f]")
MIKROTIK_INTERFACE = re.compile(r"^[A-Za-z0-9_.\-/]{1,64}$")
MIKROTIK_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
MIKROTIK_COMMENT_UNSAFE = re.compile(r"[\n\r;`|&$\[\]]")
DESTRUCTIVE_PLAN_PATTERNS = (
    "reload",
    "erase",
    "delete",
    "format",
    "reset",
    "shutdown",
    "username",
    "password",
    "enable secret",
)
DESTRUCTIVE_MIKROTIK_PATTERNS = (
    "/system reset-configuration",
    "/system reboot",
    "/file",
    "/tool",
    "/user",
    "password",
    "policy",
    "fetch",
    "import",
    "export file",
)
BLOCK_APPROVAL_STATUSES = {"blocked", "rejected", "archived"}
CISCO_INTERFACE_PLAN_TYPES = {"cisco_interface_description", "cisco_access_port"}


def create_vlan_plan(
    device_ip: str,
    vlan_id: int,
    name: str,
    ports: str | None = None,
) -> ChangePlanResult:
    init_db()
    _validate_vlan_id(vlan_id)
    safe_name = _validate_vlan_name(name)
    safe_ports = _validate_ports(ports)

    with get_session() as session:
        device = session.scalar(
            select(Device)
            .options(selectinload(Device.command_runs))
            .where(Device.ip_address == device_ip)
        )
        if device is None:
            raise ConfigPlanError(
                f"Device {device_ip} is not in inventory. Run `python main.py scan` first."
            )

        proposed = _vlan_commands(vlan_id, safe_name, safe_ports)
        rollback = _vlan_rollback(vlan_id, safe_ports)
        _validate_planning_commands(proposed + rollback)
        findings = validate_vlan_plan(device, vlan_id, safe_name, safe_ports)
        findings.extend(_topology_findings_for_planned_commands(device, "vlan", proposed, rollback))
        status = _status_from_findings(findings)

        plan = ChangePlan(
            device=device,
            plan_type="vlan",
            title=f"Create VLAN {vlan_id} {safe_name} on {device.ip_address}",
            description=_description(device.ip_address, vlan_id, safe_name, safe_ports),
            risk_level="medium" if safe_ports else "low",
            status=status,
            proposed_commands="\n".join(proposed),
            rollback_commands="\n".join(rollback),
            validation_findings=json.dumps([finding.model_dump(mode="json") for finding in findings]),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(plan)
        session.commit()
        saved_plan = session.scalar(
            select(ChangePlan)
            .options(selectinload(ChangePlan.device), selectinload(ChangePlan.approval_logs))
            .where(ChangePlan.id == plan.id)
        )
        if saved_plan is None:
            raise ConfigPlanError("Change plan was saved but could not be reloaded.")
        return ChangePlanResult(plan=saved_plan, findings=findings)


def create_mikrotik_address_plan(
    device_ip: str,
    interface: str,
    address: str,
    comment: str | None = None,
) -> ChangePlanResult:
    init_db()
    safe_interface = _validate_mikrotik_interface(interface)
    safe_address = _validate_mikrotik_address(address)
    safe_comment = _validate_mikrotik_comment(comment)

    with get_session() as session:
        device = session.scalar(
            select(Device)
            .options(
                selectinload(Device.command_runs),
                selectinload(Device.credentials),
            )
            .where(Device.ip_address == device_ip)
        )
        if device is None:
            raise ConfigPlanError(
                f"Device {device_ip} is not in inventory. Run `python main.py scan` first."
            )

        proposed = _mikrotik_address_commands(safe_address, safe_interface, safe_comment)
        rollback = _mikrotik_address_rollback(safe_address, safe_interface)
        _validate_mikrotik_planning_commands(proposed, rollback)
        findings = validate_mikrotik_address_plan(device, safe_interface, safe_address)
        findings.extend(_topology_findings_for_planned_commands(device, "mikrotik_address", proposed, rollback))
        status = _status_from_findings(findings)

        plan = ChangePlan(
            device=device,
            plan_type="mikrotik_address",
            title=f"MikroTik address plan: {safe_address} on {safe_interface}",
            description=f"Plan only: add RouterOS IP address {safe_address} to interface {safe_interface} on {device.ip_address}.",
            risk_level="medium",
            status=status,
            proposed_commands="\n".join(proposed),
            rollback_commands="\n".join(rollback),
            validation_findings=json.dumps([finding.model_dump(mode="json") for finding in findings]),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(plan)
        session.commit()
        saved_plan = session.scalar(
            select(ChangePlan)
            .options(
                selectinload(ChangePlan.device),
                selectinload(ChangePlan.approval_logs),
                selectinload(ChangePlan.execution_logs),
            )
            .where(ChangePlan.id == plan.id)
        )
        if saved_plan is None:
            raise ConfigPlanError("Change plan was saved but could not be reloaded.")
        return ChangePlanResult(plan=saved_plan, findings=findings)


def create_cisco_description_plan(
    device_ip: str,
    interface: str,
    description: str,
) -> ChangePlanResult:
    init_db()
    safe_interface = _validate_cisco_interface(interface)
    safe_description = _validate_cisco_description(description, required=True)

    with get_session() as session:
        device = session.scalar(
            select(Device)
            .options(selectinload(Device.command_runs))
            .where(Device.ip_address == device_ip)
        )
        if device is None:
            raise ConfigPlanError(
                f"Device {device_ip} is not in inventory. Run `python main.py scan` first."
            )

        proposed = _cisco_description_commands(safe_interface, safe_description)
        rollback = _cisco_description_rollback(safe_interface)
        _validate_cisco_interface_planning_commands(proposed, rollback, vlan_id=None, description=safe_description)
        findings = validate_cisco_interface_plan(device, safe_interface, vlan_id=None, access_port=False)
        findings.extend(_topology_findings_for_planned_commands(device, "cisco_interface_description", proposed, rollback))
        status = _status_from_findings(findings)

        plan = ChangePlan(
            device=device,
            plan_type="cisco_interface_description",
            title=f"Cisco description plan: {safe_interface}",
            description=f"Plan only: set interface description on {safe_interface} for {device.ip_address}.",
            risk_level="low",
            status=status,
            proposed_commands="\n".join(proposed),
            rollback_commands="\n".join(rollback),
            validation_findings=json.dumps([finding.model_dump(mode="json") for finding in findings]),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(plan)
        session.commit()
        saved_plan = _reload_plan(session, plan.id)
        return ChangePlanResult(plan=saved_plan, findings=findings)


def create_cisco_access_port_plan(
    device_ip: str,
    interface: str,
    vlan_id: int,
    description: str | None = None,
) -> ChangePlanResult:
    init_db()
    _validate_vlan_id(vlan_id)
    safe_interface = _validate_cisco_interface(interface)
    safe_description = _validate_cisco_description(description, required=False)

    with get_session() as session:
        device = session.scalar(
            select(Device)
            .options(selectinload(Device.command_runs))
            .where(Device.ip_address == device_ip)
        )
        if device is None:
            raise ConfigPlanError(
                f"Device {device_ip} is not in inventory. Run `python main.py scan` first."
            )

        proposed = _cisco_access_port_commands(safe_interface, vlan_id, safe_description)
        rollback = _cisco_access_port_rollback(safe_interface, vlan_id, include_description=bool(safe_description))
        _validate_cisco_interface_planning_commands(proposed, rollback, vlan_id=vlan_id, description=safe_description)
        findings = validate_cisco_interface_plan(device, safe_interface, vlan_id=vlan_id, access_port=True)
        findings.extend(_topology_findings_for_planned_commands(device, "cisco_access_port", proposed, rollback))
        status = _status_from_findings(findings)

        plan = ChangePlan(
            device=device,
            plan_type="cisco_access_port",
            title=f"Cisco access port plan: {safe_interface} -> VLAN {vlan_id}",
            description=(
                f"Plan only: configure {safe_interface} as an access port in VLAN {vlan_id} on {device.ip_address}. "
                "Changing access VLAN can disconnect attached clients if used incorrectly."
            ),
            risk_level="medium",
            status=status,
            proposed_commands="\n".join(proposed),
            rollback_commands="\n".join(rollback),
            validation_findings=json.dumps([finding.model_dump(mode="json") for finding in findings]),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(plan)
        session.commit()
        saved_plan = _reload_plan(session, plan.id)
        return ChangePlanResult(plan=saved_plan, findings=findings)


def create_mikrotik_dhcp_plan(
    device_ip: str,
    name: str,
    interface: str,
    network: str,
    gateway: str,
    pool_name: str,
    pool_range: str,
    dns: str | None = None,
    comment: str | None = None,
) -> ChangePlanResult:
    init_db()
    safe_name = _validate_mikrotik_safe_name(name, "DHCP server name")
    safe_pool_name = _validate_mikrotik_safe_name(pool_name, "Pool name")
    safe_interface = _validate_mikrotik_interface(interface)
    safe_network = _validate_mikrotik_dhcp_network(network)
    safe_gateway = _validate_gateway_in_network(gateway, safe_network)
    safe_pool_range = _validate_pool_range(pool_range, safe_network)
    safe_dns = _validate_dns_servers(dns)
    safe_comment = _validate_mikrotik_comment(comment)

    with get_session() as session:
        device = session.scalar(
            select(Device)
            .options(selectinload(Device.command_runs), selectinload(Device.credentials))
            .where(Device.ip_address == device_ip)
        )
        if device is None:
            raise ConfigPlanError(
                f"Device {device_ip} is not in inventory. Run `python main.py scan` first."
            )

        proposed = _mikrotik_dhcp_commands(
            safe_name,
            safe_interface,
            safe_network,
            safe_gateway,
            safe_pool_name,
            safe_pool_range,
            safe_dns,
            safe_comment,
        )
        rollback = _mikrotik_dhcp_rollback(safe_name, safe_network, safe_pool_name)
        _validate_mikrotik_dhcp_planning_commands(proposed, rollback)
        findings = validate_mikrotik_dhcp_plan(
            device=device,
            name=safe_name,
            interface=safe_interface,
            network=safe_network,
            gateway=safe_gateway,
            pool_name=safe_pool_name,
        )
        findings.extend(_topology_findings_for_planned_commands(device, "mikrotik_dhcp_server", proposed, rollback))
        status = _status_from_findings(findings)
        plan = ChangePlan(
            device=device,
            plan_type="mikrotik_dhcp_server",
            title=f"MikroTik DHCP plan: {safe_name} on {safe_interface}",
            description=(
                f"Plan only: create DHCP server `{safe_name}` on `{safe_interface}` for {safe_network}. "
                "DHCP changes can affect client addressing. Verify network, gateway, and pool range before execution."
            ),
            risk_level="medium",
            status=status,
            proposed_commands="\n".join(proposed),
            rollback_commands="\n".join(rollback),
            validation_findings=json.dumps([finding.model_dump(mode="json") for finding in findings]),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(plan)
        session.commit()
        saved_plan = _reload_plan(session, plan.id)
        return ChangePlanResult(plan=saved_plan, findings=findings)


def validate_mikrotik_dhcp_planning_commands(proposed: list[str], rollback: list[str]) -> None:
    _validate_mikrotik_dhcp_planning_commands(proposed, rollback)


def validate_vlan_plan(
    device: Device,
    vlan_id: int,
    name: str,
    ports: str | None,
) -> list[DiagnosticFinding]:
    findings: list[DiagnosticFinding] = []

    vendor_text = f"{device.vendor_guess} {device.device_type_guess}".lower()
    if "cisco" not in vendor_text and "unknown" not in vendor_text:
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="Device does not look Cisco-compatible",
                detail="Phase 7 only supports Cisco IOS VLAN planning.",
                evidence=[f"Vendor/type: {device.vendor_guess} / {device.device_type_guess}"],
                recommendation="Manually verify platform before using this plan.",
            )
        )
    elif "cisco" not in vendor_text:
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="Cisco platform is unconfirmed",
                detail="Device exists, but stored inventory does not confirm Cisco IOS.",
                evidence=[f"Vendor/type: {device.vendor_guess} / {device.device_type_guess}"],
                recommendation=f"Run `python main.py connect collect {device.ip_address}` if credentials are stored.",
            )
        )

    history = _recent_successful_command_outputs(device.command_runs)
    vlan_output = history.get("show vlan brief")
    status_output = history.get("show interfaces status")
    trunk_output = history.get("show interfaces trunk")

    if vlan_output is None and status_output is None and trunk_output is None:
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="Validation data is incomplete",
                detail="No recent read-only Cisco collection output is stored for VLAN/interface validation.",
                recommendation=f"Run `python main.py connect collect {device.ip_address}`.",
            )
        )
    if vlan_output is not None:
        if re.search(rf"(^|\s){vlan_id}(\s|$)", vlan_output):
            findings.append(
                DiagnosticFinding(
                    severity="medium",
                    title="VLAN may already exist",
                    detail=f"VLAN {vlan_id} appears in stored `show vlan brief` output.",
                )
            )
        else:
            findings.append(
                DiagnosticFinding(
                    severity="info",
                    title="VLAN not found in stored VLAN output",
                    detail=f"VLAN {vlan_id} was not seen in stored `show vlan brief` output.",
                )
            )
    else:
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="VLAN existence not verified",
                detail="No stored `show vlan brief` output is available.",
            )
        )

    if ports:
        if status_output is None:
            findings.append(
                DiagnosticFinding(
                    severity="info",
                    title="Interface existence not verified",
                    detail="No stored `show interfaces status` output is available.",
                )
            )
        if trunk_output is None:
            findings.append(
                DiagnosticFinding(
                    severity="info",
                    title="Trunk status not verified",
                    detail="No stored `show interfaces trunk` output is available.",
                )
            )
        elif _ports_may_overlap_trunks(ports, trunk_output):
            findings.append(
                DiagnosticFinding(
                    severity="medium",
                    title="Selected ports may include trunk ports",
                    detail="Stored trunk output contains text that may overlap the requested port range.",
                    evidence=[f"Requested ports: {ports}"],
                )
            )

    if not findings:
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="Plan validation completed",
                detail="Stored data did not reveal obvious conflicts.",
            )
        )
    return findings


def validate_mikrotik_address_plan(
    device: Device,
    interface: str,
    address: str,
) -> list[DiagnosticFinding]:
    findings: list[DiagnosticFinding] = []

    vendor_text = f"{device.vendor_guess} {device.device_type_guess}".lower()
    has_mikrotik_credential = any(
        credential.platform_hint == "mikrotik_routeros"
        for credential in device.credentials
    )
    if "mikrotik" not in vendor_text and not has_mikrotik_credential:
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="MikroTik platform is unconfirmed",
                detail="Inventory and saved credentials do not confirm RouterOS.",
                evidence=[f"Vendor/type: {device.vendor_guess} / {device.device_type_guess}"],
                recommendation=f"Run `python main.py credentials add {device.ip_address}` with platform `mikrotik_routeros` if appropriate.",
            )
        )
    if device.credentials and not has_mikrotik_credential:
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="Saved credentials are not MikroTik RouterOS",
                detail="Credentials exist, but none have platform `mikrotik_routeros`.",
            )
        )

    history = _recent_successful_command_outputs(device.command_runs)
    interface_output = history.get("/interface print")
    address_output = history.get("/ip address print")
    if interface_output is None and address_output is None:
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="Validation incomplete",
                detail="No stored RouterOS `/interface print` or `/ip address print` output is available.",
                recommendation=f"Run `python main.py connect collect {device.ip_address}`.",
            )
        )
    if interface_output is None:
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="Interface existence not verified",
                detail="No stored `/interface print` output is available.",
            )
        )
    elif interface.lower() not in interface_output.lower():
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="Interface not found in stored output",
                detail=f"Interface `{interface}` was not found in stored `/interface print` output.",
            )
        )
    else:
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="Interface appears in stored output",
                detail=f"Interface `{interface}` was found in stored `/interface print` output.",
            )
        )

    if address_output is None:
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="Address existence not verified",
                detail="No stored `/ip address print` output is available.",
            )
        )
    elif address in address_output:
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="Address may already exist",
                detail=f"Address `{address}` appears in stored `/ip address print` output.",
            )
        )
    else:
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="Address not found in stored output",
                detail=f"Address `{address}` was not seen in stored `/ip address print` output.",
            )
        )
    return findings


def validate_cisco_interface_plan(
    device: Device,
    interface: str,
    vlan_id: int | None,
    access_port: bool,
) -> list[DiagnosticFinding]:
    findings: list[DiagnosticFinding] = []
    vendor_text = f"{device.vendor_guess} {device.device_type_guess}".lower()
    if "cisco" not in vendor_text and "unknown" not in vendor_text:
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="Device does not look Cisco-compatible",
                detail="Cisco interface planning requires a Cisco IOS-compatible device.",
                evidence=[f"Vendor/type: {device.vendor_guess} / {device.device_type_guess}"],
            )
        )
    elif "cisco" not in vendor_text:
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="Cisco platform is unconfirmed",
                detail="Device exists, but stored inventory does not confirm Cisco IOS.",
                recommendation=f"Run `python main.py connect collect {device.ip_address}` if credentials are stored.",
            )
        )

    history = _recent_successful_command_outputs(device.command_runs)
    status_output = history.get("show interfaces status")
    trunk_output = history.get("show interfaces trunk")
    vlan_output = history.get("show vlan brief")

    if status_output is None and trunk_output is None:
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="Validation incomplete",
                detail="No stored Cisco interface evidence is available.",
                recommendation=f"Run `python main.py connect collect {device.ip_address}`.",
            )
        )

    if status_output is None:
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="Interface existence not verified",
                detail="No stored `show interfaces status` output is available.",
                recommendation=f"Run `python main.py connect collect {device.ip_address}`.",
            )
        )
    elif not _interface_in_status_output(interface, status_output):
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="Interface not found in stored evidence",
                detail=f"Interface `{interface}` was not found in stored `show interfaces status` output.",
            )
        )
    else:
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="Interface appears in stored evidence",
                detail=f"Interface `{interface}` appears in stored `show interfaces status` output.",
            )
        )

    if trunk_output is None:
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="Trunk status not verified",
                detail="No stored `show interfaces trunk` output is available.",
                recommendation=f"Run `python main.py connect collect {device.ip_address}`.",
            )
        )
    elif _interface_in_trunk_output(interface, trunk_output):
        findings.append(
            DiagnosticFinding(
                severity="high" if access_port else "medium",
                title="Interface appears to be a trunk",
                detail=f"Stored `show interfaces trunk` output includes `{interface}`.",
                recommendation="Do not convert trunk links without a separate reviewed plan.",
            )
        )

    if access_port and vlan_id is not None:
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="Rollback is basic",
                detail="Rollback is basic and may not restore previous interface state unless read-only evidence exists.",
                recommendation=f"Run `python main.py connect collect {device.ip_address}` before approval.",
            )
        )
        if vlan_output is None:
            findings.append(
                DiagnosticFinding(
                    severity="medium",
                    title="Target VLAN not verified",
                    detail="No stored `show vlan brief` output is available.",
                    recommendation=f"Run `python main.py connect collect {device.ip_address}`.",
                )
            )
        elif not re.search(rf"(^|\s){vlan_id}(\s|$)", vlan_output):
            findings.append(
                DiagnosticFinding(
                    severity="medium",
                    title="Target VLAN is not visible",
                    detail="Target VLAN is not visible in stored VLAN evidence. Create VLAN first or collect updated evidence.",
                    evidence=[f"VLAN: {vlan_id}"],
                )
            )
        else:
            findings.append(
                DiagnosticFinding(
                    severity="info",
                    title="Target VLAN appears in stored evidence",
                    detail=f"VLAN {vlan_id} appears in stored `show vlan brief` output.",
                )
            )

    if not findings:
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="Plan validation completed",
                detail="Stored data did not reveal obvious conflicts.",
            )
        )
    return findings


def validate_mikrotik_dhcp_plan(
    device: Device,
    name: str,
    interface: str,
    network: str,
    gateway: str,
    pool_name: str,
) -> list[DiagnosticFinding]:
    findings: list[DiagnosticFinding] = []
    vendor_text = f"{device.vendor_guess} {device.device_type_guess}".lower()
    if "mikrotik" not in vendor_text and "unknown" not in vendor_text:
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="MikroTik platform is unconfirmed",
                detail="Inventory does not confirm RouterOS.",
                evidence=[f"Vendor/type: {device.vendor_guess} / {device.device_type_guess}"],
                recommendation=f"Run `python main.py connect collect {device.ip_address}` if credentials are stored.",
            )
        )

    history = _recent_successful_command_outputs(device.command_runs)
    interface_output = history.get("/interface print")
    pool_output = history.get("/ip pool print")
    dhcp_output = history.get("/ip dhcp-server print")
    dhcp_network_output = history.get("/ip dhcp-server network print")
    address_output = history.get("/ip address print")
    missing = [
        command
        for command, output in (
            ("/interface print", interface_output),
            ("/ip pool print", pool_output),
            ("/ip dhcp-server print", dhcp_output),
            ("/ip dhcp-server network print", dhcp_network_output),
            ("/ip address print", address_output),
        )
        if output is None
    ]
    if missing:
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="Validation incomplete",
                detail="Stored read-only MikroTik DHCP evidence is missing: " + ", ".join(missing),
                recommendation=f"Run `python main.py connect collect {device.ip_address}`.",
            )
        )
    if interface_output is not None and interface.lower() not in interface_output.lower():
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="Interface not found in stored output",
                detail=f"Interface `{interface}` was not found in stored `/interface print` output.",
            )
        )
    if pool_output is not None and _routeros_name_in_output(pool_name, pool_output):
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="Pool name may already exist",
                detail=f"Pool `{pool_name}` appears in stored `/ip pool print` output.",
            )
        )
    if dhcp_output is not None and _routeros_name_in_output(name, dhcp_output):
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="DHCP server name may already exist",
                detail=f"DHCP server `{name}` appears in stored `/ip dhcp-server print` output.",
            )
        )
    if dhcp_network_output is not None and network in dhcp_network_output:
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="DHCP network may already exist",
                detail=f"Network `{network}` appears in stored `/ip dhcp-server network print` output.",
            )
        )
    if address_output is not None and gateway not in address_output:
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="Gateway address not found",
                detail="Gateway IP is not found in stored address evidence. Create/verify gateway address before DHCP.",
                evidence=[f"Gateway: {gateway}"],
            )
        )
    if not findings:
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="Plan validation completed",
                detail="Stored data did not reveal obvious DHCP conflicts.",
            )
        )
    return findings


def get_change_plan(plan_id: int) -> ChangePlan | None:
    init_db()
    with get_session() as session:
        return session.scalar(
            select(ChangePlan)
            .options(
                selectinload(ChangePlan.device),
                selectinload(ChangePlan.approval_logs),
                selectinload(ChangePlan.execution_logs),
            )
            .where(ChangePlan.id == plan_id)
        )


def run_preflight(plan_id: int, refresh: bool = False) -> ChangePlanResult:
    init_db()
    with get_session() as session:
        plan = session.scalar(
            select(ChangePlan)
            .options(
                selectinload(ChangePlan.device).selectinload(Device.command_runs),
                selectinload(ChangePlan.device).selectinload(Device.credentials),
                selectinload(ChangePlan.approval_logs),
            )
            .where(ChangePlan.id == plan_id)
        )
        if plan is None:
            raise ConfigPlanError(f"Change plan {plan_id} not found.")

        refresh_findings: list[DiagnosticFinding] = []
        if refresh and plan.status == "approved":
            refresh_findings = _run_readonly_refresh(plan)
            session.expire_all()
            plan = session.scalar(
                select(ChangePlan)
                .options(
                    selectinload(ChangePlan.device).selectinload(Device.command_runs),
                    selectinload(ChangePlan.device).selectinload(Device.credentials),
                    selectinload(ChangePlan.approval_logs),
                )
                .where(ChangePlan.id == plan_id)
            )
            if plan is None:
                raise ConfigPlanError(f"Change plan {plan_id} not found after refresh.")
        elif refresh:
            refresh_findings = [
                DiagnosticFinding(
                    severity="high",
                    title="Read-only refresh skipped",
                    detail="Preflight refresh requires an approved plan. No connection was attempted.",
                )
            ]

        findings = preflight_findings(plan, refresh_findings=refresh_findings)
        status = _preflight_status(findings)
        summary = _preflight_summary(status, findings)
        plan.preflight_status = status
        plan.preflight_checked_at = datetime.now(timezone.utc)
        plan.preflight_summary = summary
        plan.updated_at = datetime.now(timezone.utc)
        session.commit()
        return ChangePlanResult(plan=_reload_plan(session, plan.id), findings=findings)


def preflight_findings(
    plan: ChangePlan,
    refresh_findings: list[DiagnosticFinding] | None = None,
) -> list[DiagnosticFinding]:
    findings: list[DiagnosticFinding] = list(refresh_findings or [])
    if plan.status != "approved":
        recommendation = (
            f"Run `python main.py plan approve {plan.id}` after review."
            if plan.status not in {"blocked", "rejected", "archived"}
            else "Create a new plan or review the lifecycle decision before future preflight."
        )
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="Plan is not approved",
                detail=f"Plan status is `{plan.status}`. Preflight requires status `approved`.",
                recommendation=recommendation,
            )
        )
    if plan.device is None:
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="Device is missing",
                detail="The plan target device no longer exists in inventory.",
            )
        )
        return findings
    if not plan.device.credentials:
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="No credentials stored",
                detail="Read-only refresh cannot run without stored credentials.",
                recommendation=f"Run `python main.py credentials add {plan.device.ip_address}`.",
            )
        )
    if not plan.rollback_commands.strip():
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="Rollback commands missing",
                detail="Plan cannot pass preflight without rollback commands.",
            )
        )
    if not plan.proposed_commands.strip():
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="Proposed commands missing",
                detail="Plan cannot pass preflight without proposed commands.",
            )
        )
    if plan.plan_type not in {"custom_routeros_plan", "custom_cisco_plan"}:
        try:
            _validate_planning_commands(plan.proposed_commands.splitlines() + plan.rollback_commands.splitlines())
        except ConfigPlanError as exc:
            findings.append(
                DiagnosticFinding(
                    severity="high",
                    title="Unsafe planned command detected",
                    detail=str(exc),
                )
            )

    if plan.plan_type == "vlan":
        findings.extend(_vlan_preflight_findings(plan))
    elif plan.plan_type == "mikrotik_address":
        findings.extend(_mikrotik_address_preflight_findings(plan))
        findings.extend(_topology_findings_for_existing_plan(plan))
    elif plan.plan_type == "mikrotik_dhcp_server":
        findings.extend(_mikrotik_dhcp_preflight_findings(plan))
        findings.extend(_topology_findings_for_existing_plan(plan))
    elif plan.plan_type in CISCO_INTERFACE_PLAN_TYPES:
        findings.extend(_cisco_interface_preflight_findings(plan))
        if plan.plan_type == "cisco_access_port":
            findings.extend(_topology_findings_for_existing_plan(plan))
    elif plan.plan_type in {"custom_routeros_plan", "custom_cisco_plan"}:
        findings.extend(_custom_plan_preflight_findings(plan))
    else:
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="Unsupported plan type",
                detail=f"Preflight/execution for this plan type is not implemented yet: `{plan.plan_type}`.",
            )
        )

    if not findings:
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="Preflight passed",
                detail="Stored evidence did not reveal blockers.",
            )
        )
    return findings


def list_change_plans() -> list[ChangePlan]:
    init_db()
    with get_session() as session:
        return list(
            session.scalars(
                select(ChangePlan)
                .options(selectinload(ChangePlan.device), selectinload(ChangePlan.execution_logs))
                .order_by(ChangePlan.created_at.desc())
            ).all()
        )


def review_change_plan(plan_id: int, note: str | None = None) -> ChangePlan:
    return _transition_plan(plan_id, "reviewed", note=note)


def reject_change_plan(plan_id: int, note: str | None = None) -> ChangePlan:
    return _transition_plan(plan_id, "rejected", note=note)


def archive_change_plan(plan_id: int, note: str | None = None) -> ChangePlan:
    return _transition_plan(plan_id, "archived", note=note)


def approval_warnings(plan: ChangePlan) -> list[str]:
    findings = findings_for_plan(plan)
    warnings: list[str] = []
    if any("incomplete" in finding.title.lower() or "not verified" in finding.title.lower() for finding in findings):
        warnings.append("Validation is incomplete. You are approving a plan without full device evidence.")
    if any(finding.severity == "medium" for finding in findings):
        warnings.append("Medium-severity validation warnings are present.")
    return warnings


def approve_change_plan(plan_id: int, note: str | None = None) -> ChangePlan:
    init_db()
    with get_session() as session:
        plan = session.scalar(
            select(ChangePlan)
            .options(
                selectinload(ChangePlan.device),
                selectinload(ChangePlan.approval_logs),
                selectinload(ChangePlan.execution_logs),
            )
            .where(ChangePlan.id == plan_id)
        )
        if plan is None:
            raise ConfigPlanError(f"Change plan {plan_id} not found.")
        _validate_approval_allowed(plan)
        now = datetime.now(timezone.utc)
        plan.status = "approved"
        plan.updated_at = now
        session.add(ApprovalLog(plan=plan, action="approved", note=note, created_at=now))
        session.commit()
        return _reload_plan(session, plan.id)


def findings_for_plan(plan: ChangePlan) -> list[DiagnosticFinding]:
    try:
        raw = json.loads(plan.validation_findings or "[]")
    except json.JSONDecodeError:
        return []
    return [DiagnosticFinding(**item) for item in raw]


def _topology_findings_for_planned_commands(
    device: Device,
    plan_type: str,
    proposed: list[str],
    rollback: list[str],
) -> list[DiagnosticFinding]:
    plan = SimpleNamespace(
        device=device,
        plan_type=plan_type,
        proposed_commands="\n".join(proposed),
        rollback_commands="\n".join(rollback),
    )
    return _topology_findings_for_existing_plan(plan)


def _topology_findings_for_existing_plan(plan: ChangePlan) -> list[DiagnosticFinding]:
    try:
        from app.services.topology_awareness import analyze_plan_topology_risk

        return analyze_plan_topology_risk(plan)
    except Exception as exc:
        return [
            DiagnosticFinding(
                severity="info",
                title="Topology-aware analysis unavailable",
                detail=f"Topology-aware checks could not run: {exc}",
            )
        ]


def _custom_plan_preflight_findings(plan: ChangePlan) -> list[DiagnosticFinding]:
    findings: list[DiagnosticFinding] = []
    metadata = metadata_for_plan(plan)
    platform = metadata.get("platform") or ("mikrotik_routeros" if plan.plan_type == "custom_routeros_plan" else "cisco_ios")
    if plan.device is None:
        return [DiagnosticFinding(severity="high", title="Device is missing", detail="The plan target device no longer exists in inventory.")]
    if not any(credential.platform_hint == platform for credential in plan.device.credentials):
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="Platform credentials missing",
                detail=f"Custom plan requires saved `{platform}` SSH credentials.",
            )
        )
    proposed = [line.strip() for line in (plan.proposed_commands or "").splitlines() if line.strip()]
    rollback = [line.strip() for line in (plan.rollback_commands or "").splitlines() if line.strip()]
    classifications = classify_commands(proposed + rollback, platform)
    if has_blocked_command(classifications):
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="Blocked custom command",
                detail="One or more generated commands are blocked as security abuse.",
                evidence=[item.command for item in classifications if item.category == "blocked_security_abuse"],
            )
        )
    if has_double_confirmation(classifications):
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="Double confirmation required",
                detail="This custom plan may disrupt routing/firewall/NAT/DHCP/management behavior.",
                recommendation="Execution must include both custom confirmation phrases.",
            )
        )
    for command in metadata.get("precheck_commands", []):
        try:
            validate_precheck_command(str(command), platform)
        except ValueError as exc:
            findings.append(DiagnosticFinding(severity="high", title="Invalid precheck command", detail=str(exc)))
    verification = metadata.get("verification_commands", [])
    if not verification:
        findings.append(DiagnosticFinding(severity="high", title="Verification commands missing", detail="Custom execution requires read-only verification commands."))
    for command in verification:
        try:
            validate_verification_command(str(command), platform)
        except ValueError as exc:
            findings.append(DiagnosticFinding(severity="high", title="Invalid verification command", detail=str(exc)))
    if not rollback:
        findings.append(DiagnosticFinding(severity="high", title="Rollback commands missing", detail="Custom execution requires rollback commands."))
    if not findings:
        findings.append(DiagnosticFinding(severity="info", title="Custom preflight passed", detail="Custom command validation passed. Backup snapshot is still mandatory at execution."))
    return findings


def _transition_plan(plan_id: int, status: str, note: str | None = None) -> ChangePlan:
    init_db()
    with get_session() as session:
        plan = session.scalar(
            select(ChangePlan)
            .options(
                selectinload(ChangePlan.device),
                selectinload(ChangePlan.approval_logs),
                selectinload(ChangePlan.execution_logs),
            )
            .where(ChangePlan.id == plan_id)
        )
        if plan is None:
            raise ConfigPlanError(f"Change plan {plan_id} not found.")
        now = datetime.now(timezone.utc)
        plan.status = status
        plan.updated_at = now
        session.add(ApprovalLog(plan=plan, action=status, note=note, created_at=now))
        session.commit()
        return _reload_plan(session, plan.id)


def _reload_plan(session, plan_id: int) -> ChangePlan:
    plan = session.scalar(
        select(ChangePlan)
        .options(
            selectinload(ChangePlan.device),
            selectinload(ChangePlan.approval_logs),
            selectinload(ChangePlan.execution_logs),
        )
        .where(ChangePlan.id == plan_id)
    )
    if plan is None:
        raise ConfigPlanError(f"Change plan {plan_id} not found after update.")
    return plan


def _validate_approval_allowed(plan: ChangePlan) -> None:
    if plan.status in BLOCK_APPROVAL_STATUSES:
        raise ConfigPlanError(f"Cannot approve a plan with status `{plan.status}`.")
    if not plan.proposed_commands.strip():
        raise ConfigPlanError("Cannot approve a plan with empty proposed commands.")
    if not plan.rollback_commands.strip():
        raise ConfigPlanError("Cannot approve a plan with empty rollback commands.")
    findings = findings_for_plan(plan)
    if any(finding.severity == "high" for finding in findings):
        raise ConfigPlanError("Cannot approve a plan with high-severity validation blockers.")
    commands = plan.proposed_commands.splitlines() + plan.rollback_commands.splitlines()
    if plan.plan_type in {"custom_routeros_plan", "custom_cisco_plan"}:
        metadata = metadata_for_plan(plan)
        platform = metadata.get("platform") or ("mikrotik_routeros" if plan.plan_type == "custom_routeros_plan" else "cisco_ios")
        classifications = classify_commands(commands, platform)
        if has_blocked_command(classifications):
            raise ConfigPlanError("Cannot approve a custom plan with blocked security-abuse commands.")
    else:
        _validate_planning_commands(commands)


def _run_readonly_refresh(plan: ChangePlan) -> list[DiagnosticFinding]:
    if plan.device is None:
        return [
            DiagnosticFinding(
                severity="high",
                title="Read-only refresh skipped",
                detail="Plan device is missing.",
            )
        ]
    if not plan.device.credentials:
        return [
            DiagnosticFinding(
                severity="medium",
                title="Read-only refresh skipped",
                detail="No stored credentials exist for the device.",
                recommendation=f"Run `python main.py credentials add {plan.device.ip_address}`.",
            )
        ]
    if plan.plan_type == "mikrotik_address":
        return _run_mikrotik_preflight_refresh(plan)
    if plan.plan_type == "mikrotik_dhcp_server":
        return _run_mikrotik_dhcp_preflight_refresh(plan)
    if plan.plan_type in CISCO_INTERFACE_PLAN_TYPES:
        return _run_cisco_interface_preflight_refresh(plan)
    if plan.plan_type in {"custom_routeros_plan", "custom_cisco_plan"}:
        return _run_custom_preflight_refresh(plan)
    try:
        result = run_readonly_profile_collection(plan.device.ip_address)
    except DeviceConnectionError as exc:
        return [
            DiagnosticFinding(
                severity="medium",
                title="Read-only refresh failed",
                detail=str(exc),
                recommendation=f"Run `python main.py connect collect {plan.device.ip_address}` after fixing access.",
            )
        ]
    if result.failure_count:
        return [
            DiagnosticFinding(
                severity="medium",
                title="Read-only refresh partially failed",
                detail=f"{result.success_count} command(s) succeeded; {result.failure_count} failed.",
            )
        ]
    return [
        DiagnosticFinding(
            severity="info",
            title="Read-only refresh completed",
            detail=f"{result.success_count} allowlisted read-only command(s) completed.",
        )
    ]


def _run_custom_preflight_refresh(plan: ChangePlan) -> list[DiagnosticFinding]:
    if plan.device is None:
        return [DiagnosticFinding(severity="high", title="Read-only refresh skipped", detail="Plan device is missing.")]
    metadata = metadata_for_plan(plan)
    platform = metadata.get("platform") or ("mikrotik_routeros" if plan.plan_type == "custom_routeros_plan" else "cisco_ios")
    if not any(credential.platform_hint == platform for credential in plan.device.credentials):
        return [
            DiagnosticFinding(
                severity="high",
                title="Read-only refresh skipped",
                detail=f"No saved `{platform}` credentials exist for the device.",
            )
        ]
    commands = [str(command) for command in metadata.get("precheck_commands", [])]
    if not commands:
        return [DiagnosticFinding(severity="medium", title="Read-only refresh skipped", detail="Custom plan has no precheck commands.")]
    results = []
    for command in commands:
        try:
            validate_precheck_command(command, platform)
            results.append(run_readonly_command(plan.device.ip_address, command))
        except (ValueError, DeviceConnectionError) as exc:
            return [DiagnosticFinding(severity="medium", title="Read-only refresh failed", detail=str(exc))]
    failures = [result for result in results if not result.success]
    if failures:
        return [DiagnosticFinding(severity="medium", title="Read-only refresh partially failed", detail=f"{len(failures)} precheck command(s) failed.")]
    return [DiagnosticFinding(severity="info", title="Custom precheck refresh completed", detail=f"Ran {len(results)} read-only precheck command(s).")]


def _run_mikrotik_preflight_refresh(plan: ChangePlan) -> list[DiagnosticFinding]:
    if plan.device is None:
        return [
            DiagnosticFinding(
                severity="high",
                title="Read-only refresh skipped",
                detail="Plan device is missing.",
            )
        ]
    if not any(credential.platform_hint == "mikrotik_routeros" for credential in plan.device.credentials):
        return [
            DiagnosticFinding(
                severity="high",
                title="Read-only refresh skipped",
                detail="No saved `mikrotik_routeros` credentials exist for the device.",
                recommendation=f"Run `python main.py credentials add {plan.device.ip_address}` with platform `mikrotik_routeros`.",
            )
        ]
    results = []
    for command in ("/interface print", "/ip address print"):
        try:
            results.append(run_readonly_command(plan.device.ip_address, command))
        except DeviceConnectionError as exc:
            return [
                DiagnosticFinding(
                    severity="medium",
                    title="Read-only refresh failed",
                    detail=str(exc),
                    recommendation=f"Run `python main.py connect collect {plan.device.ip_address}` after fixing access.",
                )
            ]
    failures = [result for result in results if not result.success]
    if failures:
        return [
            DiagnosticFinding(
                severity="medium",
                title="Read-only refresh partially failed",
                detail=f"{len(results) - len(failures)} command(s) succeeded; {len(failures)} failed.",
            )
        ]
    return [
        DiagnosticFinding(
            severity="info",
            title="MikroTik read-only refresh completed",
            detail="Ran only `/interface print` and `/ip address print`.",
        )
    ]


def _run_mikrotik_dhcp_preflight_refresh(plan: ChangePlan) -> list[DiagnosticFinding]:
    if plan.device is None:
        return [
            DiagnosticFinding(
                severity="high",
                title="Read-only refresh skipped",
                detail="Plan device is missing.",
            )
        ]
    if not any(credential.platform_hint == "mikrotik_routeros" for credential in plan.device.credentials):
        return [
            DiagnosticFinding(
                severity="high",
                title="Read-only refresh skipped",
                detail="No saved `mikrotik_routeros` credentials exist for the device.",
                recommendation=f"Run `python main.py credentials add {plan.device.ip_address}` with platform `mikrotik_routeros`.",
            )
        ]
    commands = (
        "/interface print",
        "/ip address print",
        "/ip pool print",
        "/ip dhcp-server print",
        "/ip dhcp-server network print",
    )
    results = []
    for command in commands:
        try:
            results.append(run_readonly_command(plan.device.ip_address, command))
        except DeviceConnectionError as exc:
            return [
                DiagnosticFinding(
                    severity="medium",
                    title="Read-only refresh failed",
                    detail=str(exc),
                    recommendation=f"Run `python main.py connect collect {plan.device.ip_address}` after fixing access.",
                )
            ]
    failures = [result for result in results if not result.success]
    if failures:
        return [
            DiagnosticFinding(
                severity="medium",
                title="Read-only refresh partially failed",
                detail=f"{len(results) - len(failures)} command(s) succeeded; {len(failures)} failed.",
            )
        ]
    return [
        DiagnosticFinding(
            severity="info",
            title="MikroTik DHCP read-only refresh completed",
            detail="Ran only `/interface print`, `/ip address print`, `/ip pool print`, `/ip dhcp-server print`, and `/ip dhcp-server network print`.",
        )
    ]


def _run_cisco_interface_preflight_refresh(plan: ChangePlan) -> list[DiagnosticFinding]:
    if plan.device is None:
        return [
            DiagnosticFinding(
                severity="high",
                title="Read-only refresh skipped",
                detail="Plan device is missing.",
            )
        ]
    if not any(credential.platform_hint == "cisco_ios" for credential in plan.device.credentials):
        return [
            DiagnosticFinding(
                severity="high",
                title="Read-only refresh skipped",
                detail="No saved `cisco_ios` credentials exist for the device.",
                recommendation=f"Run `python main.py credentials add {plan.device.ip_address}` with platform `cisco_ios`.",
            )
        ]
    commands = ["show interfaces status", "show interfaces trunk"]
    if plan.plan_type == "cisco_access_port":
        commands.append("show vlan brief")
    results = []
    for command in commands:
        try:
            results.append(run_readonly_command(plan.device.ip_address, command))
        except DeviceConnectionError as exc:
            return [
                DiagnosticFinding(
                    severity="medium",
                    title="Read-only refresh failed",
                    detail=str(exc),
                    recommendation=f"Run `python main.py connect collect {plan.device.ip_address}` after fixing access.",
                )
            ]
    failures = [result for result in results if not result.success]
    if failures:
        return [
            DiagnosticFinding(
                severity="medium",
                title="Read-only refresh partially failed",
                detail=f"{len(results) - len(failures)} command(s) succeeded; {len(failures)} failed.",
            )
        ]
    return [
        DiagnosticFinding(
            severity="info",
            title="Cisco interface read-only refresh completed",
            detail=f"Ran only: {', '.join(commands)}.",
        )
    ]


def _vlan_preflight_findings(plan: ChangePlan) -> list[DiagnosticFinding]:
    findings: list[DiagnosticFinding] = []
    vlan_id = _vlan_id_from_plan(plan)
    ports = _ports_from_plan(plan)
    if vlan_id is None:
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="VLAN ID could not be parsed",
                detail="The proposed commands do not contain a valid `vlan <id>` line.",
            )
        )
        return findings
    if vlan_id < 1 or vlan_id > 4094:
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="VLAN ID is invalid",
                detail=f"VLAN ID {vlan_id} is outside 1-4094.",
            )
        )

    history = _recent_successful_command_outputs(plan.device.command_runs if plan.device else [])
    vlan_output = history.get("show vlan brief")
    status_output = history.get("show interfaces status")
    trunk_output = history.get("show interfaces trunk")

    if vlan_output is None:
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="VLAN existence not verified",
                detail="No stored successful `show vlan brief` output is available.",
                recommendation=f"Run `python main.py connect collect {plan.device.ip_address}`.",
            )
        )
    elif re.search(rf"(^|\s){vlan_id}(\s|$)", vlan_output):
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="VLAN appears to already exist",
                detail=f"VLAN {vlan_id} appears in stored `show vlan brief` output.",
            )
        )
    if ports:
        if status_output is None:
            findings.append(
                DiagnosticFinding(
                    severity="medium",
                    title="Target port existence not verified",
                    detail="No stored successful `show interfaces status` output is available.",
                    recommendation=f"Run `python main.py connect collect {plan.device.ip_address}`.",
                )
            )
        if trunk_output is None:
            findings.append(
                DiagnosticFinding(
                    severity="medium",
                    title="Target trunk status not verified",
                    detail="No stored successful `show interfaces trunk` output is available.",
                    recommendation=f"Run `python main.py connect collect {plan.device.ip_address}`.",
                )
            )
        elif _ports_may_overlap_trunks(ports, trunk_output):
            findings.append(
                DiagnosticFinding(
                    severity="high",
                    title="Target ports may be trunk ports",
                    detail="Stored trunk output suggests the requested port range may overlap trunk ports.",
                    evidence=[f"Requested ports: {ports}"],
                )
            )
    return findings


def _mikrotik_address_preflight_findings(plan: ChangePlan) -> list[DiagnosticFinding]:
    findings: list[DiagnosticFinding] = []
    if plan.device is None:
        return [
            DiagnosticFinding(
                severity="high",
                title="Device is missing",
                detail="The plan target device no longer exists in inventory.",
            )
        ]

    parsed = _mikrotik_address_plan_parts(plan)
    if parsed is None:
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="MikroTik address plan could not be parsed",
                detail="The proposed or rollback command does not match the strict RouterOS address template.",
            )
        )
        return findings
    address, interface = parsed
    try:
        _validate_mikrotik_address(address)
        _validate_mikrotik_interface(interface)
        _validate_mikrotik_planning_commands(
            plan.proposed_commands.splitlines(),
            plan.rollback_commands.splitlines(),
        )
    except ConfigPlanError as exc:
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="MikroTik command safety validation failed",
                detail=str(exc),
            )
        )

    if not plan.device.credentials:
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="No credentials stored",
                detail="MikroTik preflight requires saved `mikrotik_routeros` credentials.",
                recommendation=f"Run `python main.py credentials add {plan.device.ip_address}`.",
            )
        )
    elif not any(credential.platform_hint == "mikrotik_routeros" for credential in plan.device.credentials):
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="MikroTik credentials missing",
                detail="Saved credentials exist, but none have platform `mikrotik_routeros`.",
            )
        )

    history = _recent_successful_command_outputs(plan.device.command_runs)
    interface_output = history.get("/interface print")
    address_output = history.get("/ip address print")
    if interface_output is None:
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="Interface evidence missing",
                detail="No successful stored `/interface print` output is available.",
                recommendation=f"Run `python main.py plan preflight {plan.id} --refresh`.",
            )
        )
    elif interface.lower() not in interface_output.lower():
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="Interface not found",
                detail=f"Interface `{interface}` was not found in `/interface print` output.",
            )
        )
    else:
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="Interface found",
                detail=f"Interface `{interface}` appears in stored `/interface print` output.",
            )
        )

    if address_output is None:
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="Address evidence missing",
                detail="No successful stored `/ip address print` output is available.",
                recommendation=f"Run `python main.py plan preflight {plan.id} --refresh`.",
            )
        )
    else:
        matching_lines = [line for line in address_output.splitlines() if address in line]
        exact_line = next((line for line in matching_lines if interface.lower() in line.lower()), None)
        if exact_line:
            findings.append(
                DiagnosticFinding(
                    severity="high",
                    title="Address already assigned on target interface",
                    detail=f"`{address}` appears on `{interface}` in stored `/ip address print` output.",
                    evidence=[exact_line.strip()],
                )
            )
        elif matching_lines:
            findings.append(
                DiagnosticFinding(
                    severity="medium",
                    title="Address appears on another interface",
                    detail=f"`{address}` appears in stored `/ip address print` output, but not clearly on `{interface}`.",
                    evidence=[line.strip() for line in matching_lines[:3]],
                )
            )
        else:
            findings.append(
                DiagnosticFinding(
                    severity="info",
                    title="Address not currently assigned",
                    detail=f"`{address}` was not found in stored `/ip address print` output.",
                )
            )
    return findings


def _mikrotik_dhcp_preflight_findings(plan: ChangePlan) -> list[DiagnosticFinding]:
    findings: list[DiagnosticFinding] = []
    if plan.device is None:
        return [
            DiagnosticFinding(
                severity="high",
                title="Device is missing",
                detail="The plan target device no longer exists in inventory.",
            )
        ]

    parts = _mikrotik_dhcp_plan_parts(plan)
    if parts is None:
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="MikroTik DHCP plan could not be parsed",
                detail="The proposed or rollback commands do not match the strict RouterOS DHCP templates.",
            )
        )
        return findings
    try:
        _validate_mikrotik_dhcp_planning_commands(
            plan.proposed_commands.splitlines(),
            plan.rollback_commands.splitlines(),
        )
        _validate_mikrotik_dhcp_network(parts.network)
        _validate_gateway_in_network(parts.gateway, parts.network)
        _validate_pool_range(parts.pool_range, parts.network)
        _validate_mikrotik_interface(parts.interface)
        _validate_mikrotik_safe_name(parts.name, "DHCP server name")
        _validate_mikrotik_safe_name(parts.pool_name, "Pool name")
        _validate_dns_servers(parts.dns)
        _validate_mikrotik_comment(parts.comment)
    except ConfigPlanError as exc:
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="MikroTik DHCP command safety validation failed",
                detail=str(exc),
            )
        )

    if not plan.device.credentials:
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="No credentials stored",
                detail="MikroTik DHCP preflight requires saved `mikrotik_routeros` credentials.",
                recommendation=f"Run `python main.py credentials add {plan.device.ip_address}`.",
            )
        )
    elif not any(credential.platform_hint == "mikrotik_routeros" for credential in plan.device.credentials):
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="MikroTik credentials missing",
                detail="Saved credentials exist, but none have platform `mikrotik_routeros`.",
            )
        )

    history = _recent_successful_command_outputs(plan.device.command_runs)
    interface_output = history.get("/interface print")
    address_output = history.get("/ip address print")
    pool_output = history.get("/ip pool print")
    dhcp_output = history.get("/ip dhcp-server print")
    dhcp_network_output = history.get("/ip dhcp-server network print")
    missing = [
        command
        for command, output in (
            ("/interface print", interface_output),
            ("/ip address print", address_output),
            ("/ip pool print", pool_output),
            ("/ip dhcp-server print", dhcp_output),
            ("/ip dhcp-server network print", dhcp_network_output),
        )
        if output is None
    ]
    if missing:
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="DHCP evidence missing",
                detail="Preflight requires stored successful read-only evidence: " + ", ".join(missing),
                recommendation=f"Run `python main.py plan preflight {plan.id} --refresh`.",
            )
        )

    if interface_output is not None:
        if _routeros_token_in_output(parts.interface, interface_output):
            findings.append(
                DiagnosticFinding(
                    severity="info",
                    title="Interface found",
                    detail=f"Interface `{parts.interface}` appears in stored `/interface print` output.",
                )
            )
        else:
            findings.append(
                DiagnosticFinding(
                    severity="high",
                    title="Interface not found",
                    detail=f"Interface `{parts.interface}` was not found in stored `/interface print` output.",
                )
            )

    if address_output is not None:
        if parts.gateway in address_output:
            findings.append(
                DiagnosticFinding(
                    severity="info",
                    title="Gateway address found",
                    detail=f"Gateway `{parts.gateway}` appears in stored `/ip address print` output.",
                )
            )
        else:
            findings.append(
                DiagnosticFinding(
                    severity="medium",
                    title="Gateway address not confirmed",
                    detail="Gateway IP is inside the target network but was not found in stored `/ip address print` output.",
                    evidence=[f"Gateway: {parts.gateway}", f"Network: {parts.network}"],
                )
            )

    if pool_output is not None:
        if _routeros_name_in_output(parts.pool_name, pool_output):
            findings.append(
                DiagnosticFinding(
                    severity="high",
                    title="Pool name already exists",
                    detail=f"Pool `{parts.pool_name}` appears in stored `/ip pool print` output.",
                )
            )
        else:
            findings.append(
                DiagnosticFinding(
                    severity="info",
                    title="Pool name not found",
                    detail=f"Pool `{parts.pool_name}` was not found in stored `/ip pool print` output.",
                )
            )

    if dhcp_output is not None:
        if _routeros_name_in_output(parts.name, dhcp_output):
            findings.append(
                DiagnosticFinding(
                    severity="high",
                    title="DHCP server name already exists",
                    detail=f"DHCP server `{parts.name}` appears in stored `/ip dhcp-server print` output.",
                )
            )
        else:
            findings.append(
                DiagnosticFinding(
                    severity="info",
                    title="DHCP server name not found",
                    detail=f"DHCP server `{parts.name}` was not found in stored `/ip dhcp-server print` output.",
                )
            )

    if dhcp_network_output is not None:
        if parts.network in dhcp_network_output:
            findings.append(
                DiagnosticFinding(
                    severity="high",
                    title="DHCP network already exists",
                    detail=f"Network `{parts.network}` appears in stored `/ip dhcp-server network print` output.",
                )
            )
        else:
            findings.append(
                DiagnosticFinding(
                    severity="info",
                    title="DHCP network not found",
                    detail=f"Network `{parts.network}` was not found in stored `/ip dhcp-server network print` output.",
                )
            )
    return findings


def _cisco_interface_preflight_findings(plan: ChangePlan) -> list[DiagnosticFinding]:
    findings: list[DiagnosticFinding] = []
    if plan.device is None:
        return [
            DiagnosticFinding(
                severity="high",
                title="Device is missing",
                detail="The plan target device no longer exists in inventory.",
            )
        ]

    try:
        from app.services.config_executor import validate_cisco_interface_execution_commands

        validate_cisco_interface_execution_commands(
            plan.plan_type,
            plan.proposed_commands.splitlines(),
            plan.rollback_commands.splitlines(),
        )
    except Exception as exc:
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="Cisco interface command safety validation failed",
                detail=str(exc),
            )
        )
        return findings

    parsed = _cisco_interface_plan_parts(plan)
    if parsed is None:
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="Cisco interface plan could not be parsed",
                detail="The proposed commands do not match a supported Cisco interface template.",
            )
        )
        return findings
    interface, vlan_id, _description = parsed

    if not plan.device.credentials:
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="No credentials stored",
                detail="Cisco interface preflight requires saved `cisco_ios` credentials.",
                recommendation=f"Run `python main.py credentials add {plan.device.ip_address}`.",
            )
        )
    elif not any(credential.platform_hint == "cisco_ios" for credential in plan.device.credentials):
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="Cisco credentials missing",
                detail="Saved credentials exist, but none have platform `cisco_ios`.",
            )
        )

    history = _recent_successful_command_outputs(plan.device.command_runs)
    status_output = history.get("show interfaces status")
    trunk_output = history.get("show interfaces trunk")
    vlan_output = history.get("show vlan brief")

    if status_output is None:
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="Interface evidence missing",
                detail="No successful stored `show interfaces status` output is available.",
                recommendation=f"Run `python main.py plan preflight {plan.id} --refresh`.",
            )
        )
    elif not _interface_in_status_output(interface, status_output):
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="Interface not found",
                detail=f"Interface `{interface}` was not found in stored `show interfaces status` output.",
            )
        )
    else:
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="Interface found",
                detail=f"Interface `{interface}` appears in stored `show interfaces status` output.",
            )
        )

    if trunk_output is None:
        findings.append(
            DiagnosticFinding(
                severity="medium",
                title="Trunk evidence missing",
                detail="No successful stored `show interfaces trunk` output is available.",
                recommendation=f"Run `python main.py plan preflight {plan.id} --refresh`.",
            )
        )
    elif _interface_in_trunk_output(interface, trunk_output):
        findings.append(
            DiagnosticFinding(
                severity="high",
                title="Interface is a trunk",
                detail=f"Interface `{interface}` appears in stored `show interfaces trunk` output.",
                recommendation="Do not use this interface plan on trunk links.",
            )
        )
    else:
        findings.append(
            DiagnosticFinding(
                severity="info",
                title="Interface not seen as trunk",
                detail=f"Interface `{interface}` was not seen in stored `show interfaces trunk` output.",
            )
        )

    if plan.plan_type == "cisco_access_port":
        if vlan_id is None:
            findings.append(
                DiagnosticFinding(
                    severity="high",
                    title="VLAN ID could not be parsed",
                    detail="The access-port plan does not contain a valid `switchport access vlan <id>` command.",
                )
            )
        elif vlan_output is None:
            findings.append(
                DiagnosticFinding(
                    severity="medium",
                    title="VLAN evidence missing",
                    detail="No successful stored `show vlan brief` output is available.",
                    recommendation=f"Run `python main.py plan preflight {plan.id} --refresh`.",
                )
            )
        elif not re.search(rf"(^|\s){vlan_id}(\s|$)", vlan_output):
            findings.append(
                DiagnosticFinding(
                    severity="high",
                    title="Target VLAN missing",
                    detail=f"VLAN {vlan_id} was not found in stored `show vlan brief` output.",
                    recommendation="Create the VLAN first or collect updated evidence before approval.",
                )
            )
        else:
            findings.append(
                DiagnosticFinding(
                    severity="info",
                    title="Target VLAN found",
                    detail=f"VLAN {vlan_id} appears in stored `show vlan brief` output.",
                )
            )
    return findings


def _vlan_id_from_plan(plan: ChangePlan) -> int | None:
    match = re.search(r"(?m)^vlan\s+(\d+)\s*$", plan.proposed_commands)
    if not match:
        return None
    return int(match.group(1))


def _ports_from_plan(plan: ChangePlan) -> str | None:
    match = re.search(r"(?m)^interface range\s+(.+)$", plan.proposed_commands)
    return match.group(1).strip() if match else None


def _mikrotik_address_plan_parts(plan: ChangePlan) -> tuple[str, str] | None:
    proposed = plan.proposed_commands.strip()
    rollback = plan.rollback_commands.strip()
    proposed_match = re.fullmatch(
        r'/ip address add address=([0-9.]+/\d{1,2}) interface=([A-Za-z0-9_.\-/]+)(?: comment="[^"\n\r;`|&$\[\]]{1,64}")?',
        proposed,
    )
    if not proposed_match:
        return None
    address, interface = proposed_match.group(1), proposed_match.group(2)
    expected = rf'/ip address remove \[find address="{re.escape(address)}" interface="{re.escape(interface)}"\]'
    if not re.fullmatch(expected, rollback):
        return None
    return address, interface


def _mikrotik_dhcp_plan_parts(plan: ChangePlan) -> MikroTikDhcpPlanParts | None:
    return _mikrotik_dhcp_plan_parts_from_commands(
        plan.proposed_commands.splitlines(),
        plan.rollback_commands.splitlines(),
    )


def _mikrotik_dhcp_plan_parts_from_commands(
    proposed: list[str],
    rollback: list[str],
) -> MikroTikDhcpPlanParts | None:
    proposed = [line.strip() for line in proposed if line.strip()]
    rollback = [line.strip() for line in rollback if line.strip()]
    if len(proposed) != 3 or len(rollback) != 3:
        return None

    pool_match = re.fullmatch(
        r"/ip pool add name=([A-Za-z0-9_.-]{1,64}) ranges=([0-9.]+-[0-9.]+)",
        proposed[0],
    )
    server_match = re.fullmatch(
        r'/ip dhcp-server add name=([A-Za-z0-9_.-]{1,64}) interface=([A-Za-z0-9_.\-/]{1,64}) address-pool=([A-Za-z0-9_.-]{1,64}) disabled=no(?: comment="([^"\n\r;`|&$\[\]]{1,64})")?',
        proposed[1],
    )
    network_match = re.fullmatch(
        r"/ip dhcp-server network add address=([0-9.]+/\d{1,2}) gateway=([0-9.]+)(?: dns-server=([0-9.,]+))?",
        proposed[2],
    )
    if not pool_match or not server_match or not network_match:
        return None

    pool_name, pool_range = pool_match.group(1), pool_match.group(2)
    name, interface, server_pool_name, comment = (
        server_match.group(1),
        server_match.group(2),
        server_match.group(3),
        server_match.group(4),
    )
    network, gateway, dns = network_match.group(1), network_match.group(2), network_match.group(3)
    if server_pool_name != pool_name:
        return None
    if rollback[0] != f'/ip dhcp-server remove [find name="{name}"]':
        return None
    if rollback[1] != f'/ip dhcp-server network remove [find address="{network}"]':
        return None
    if rollback[2] != f'/ip pool remove [find name="{pool_name}"]':
        return None
    return MikroTikDhcpPlanParts(
        name=name,
        interface=interface,
        network=network,
        gateway=gateway,
        pool_name=pool_name,
        pool_range=pool_range,
        dns=dns,
        comment=comment,
    )


def _cisco_interface_plan_parts(plan: ChangePlan) -> tuple[str, int | None, str | None] | None:
    lines = [line.strip() for line in plan.proposed_commands.splitlines() if line.strip()]
    if len(lines) < 2 or not lines[0].lower().startswith("interface "):
        return None
    interface = lines[0].split(maxsplit=1)[1]
    vlan_id: int | None = None
    description: str | None = None
    for line in lines[1:]:
        vlan_match = re.fullmatch(r"switchport access vlan (\d+)", line, flags=re.IGNORECASE)
        if vlan_match:
            vlan_id = int(vlan_match.group(1))
        if line.lower().startswith("description "):
            description = line.split(maxsplit=1)[1]
    if plan.plan_type == "cisco_interface_description" and description is None:
        return None
    if plan.plan_type == "cisco_access_port" and vlan_id is None:
        return None
    return interface, vlan_id, description


def _preflight_status(findings: list[DiagnosticFinding]) -> str:
    if any(finding.severity == "high" for finding in findings):
        return "failed"
    if any(finding.severity in {"medium", "low"} for finding in findings):
        return "warning"
    return "passed"


def _preflight_summary(status: str, findings: list[DiagnosticFinding]) -> str:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    parts = ", ".join(f"{severity}={count}" for severity, count in sorted(counts.items()))
    return f"Preflight {status}. Findings: {parts or 'none'}."


def _validate_vlan_id(vlan_id: int) -> None:
    if vlan_id < 1 or vlan_id > 4094:
        raise ConfigPlanError("VLAN ID must be between 1 and 4094.")


def _validate_vlan_name(name: str) -> str:
    normalized = " ".join(name.strip().split())
    if not SAFE_VLAN_NAME.fullmatch(normalized):
        raise ConfigPlanError(
            "VLAN name must be 1-32 characters using only letters, numbers, spaces, dash, and underscore."
        )
    return normalized


def _validate_ports(ports: str | None) -> str | None:
    if ports is None or not ports.strip():
        return None
    normalized = ports.strip()
    if UNSAFE_PORT_CHARS.search(normalized) or "--" in normalized:
        raise ConfigPlanError("Ports string contains unsafe characters or operators.")
    if not PORT_FORMAT.fullmatch(normalized):
        raise ConfigPlanError("Ports string format is not recognized as a safe Cisco interface range.")
    return normalized


def _validate_cisco_interface(interface: str) -> str:
    value = interface.strip()
    if any(char in value for char in (" ", ",", "-")):
        raise ConfigPlanError("Cisco interface planning supports one interface only; ranges are not accepted.")
    if CISCO_DESCRIPTION_UNSAFE.search(value):
        raise ConfigPlanError("Cisco interface name contains unsafe characters.")
    if not CISCO_INTERFACE.fullmatch(value):
        raise ConfigPlanError("Cisco interface name is not a supported single-interface format.")
    return value


def _validate_cisco_description(description: str | None, *, required: bool) -> str | None:
    if description is None or not description.strip():
        if required:
            raise ConfigPlanError("Description is required.")
        return None
    value = " ".join(description.strip().split())
    if len(value) > 80:
        raise ConfigPlanError("Cisco interface description must be 80 characters or fewer.")
    if CISCO_DESCRIPTION_UNSAFE.search(value):
        raise ConfigPlanError("Cisco interface description contains unsafe characters.")
    return value


def _validate_planning_commands(commands: list[str]) -> None:
    for command in commands:
        lowered = command.lower().strip()
        for pattern in DESTRUCTIVE_PLAN_PATTERNS:
            if pattern in lowered:
                raise ConfigPlanError(f"Planned command blocked by safety policy: contains `{pattern}`.")


def _validate_cisco_interface_planning_commands(
    proposed: list[str],
    rollback: list[str],
    *,
    vlan_id: int | None,
    description: str | None,
) -> None:
    _validate_planning_commands(proposed + rollback)
    commands = proposed + rollback
    if any(not command.strip() for command in commands):
        raise ConfigPlanError("Planned Cisco interface commands cannot contain empty lines.")
    interface_line = proposed[0].strip() if proposed else ""
    rollback_interface_line = rollback[0].strip() if rollback else ""
    if not interface_line.startswith("interface ") or rollback_interface_line != interface_line:
        raise ConfigPlanError("Cisco interface plans must start proposed and rollback commands with the same interface.")
    interface = interface_line.removeprefix("interface ").strip()
    _validate_cisco_interface(interface)

    allowed_proposed = {interface_line}
    allowed_rollback = {interface_line}
    if vlan_id is not None:
        allowed_proposed.update(
            {
                "switchport mode access",
                f"switchport access vlan {vlan_id}",
                "spanning-tree portfast",
            }
        )
        allowed_rollback.update(
            {
                f"no switchport access vlan {vlan_id}",
                "no spanning-tree portfast",
            }
        )
    if description:
        allowed_proposed.add(f"description {description}")
        allowed_rollback.add("no description")

    for command in proposed:
        if command.strip() not in allowed_proposed:
            raise ConfigPlanError(f"Cisco proposed command is outside the allowed template: `{command}`.")
    for command in rollback:
        if command.strip() not in allowed_rollback:
            raise ConfigPlanError(f"Cisco rollback command is outside the allowed template: `{command}`.")


def _validate_mikrotik_interface(interface: str) -> str:
    value = interface.strip()
    if not MIKROTIK_INTERFACE.fullmatch(value):
        raise ConfigPlanError("MikroTik interface name contains unsafe characters.")
    return value


def _validate_mikrotik_safe_name(value: str, label: str) -> str:
    normalized = value.strip()
    if not MIKROTIK_SAFE_NAME.fullmatch(normalized):
        raise ConfigPlanError(f"{label} must use only letters, numbers, dash, underscore, and dot.")
    return normalized


def _validate_mikrotik_address(address: str) -> str:
    try:
        interface = ipaddress.ip_interface(address)
    except ValueError as exc:
        raise ConfigPlanError("Address must be a valid IPv4 interface CIDR.") from exc
    if interface.version != 4:
        raise ConfigPlanError("Only IPv4 interface CIDRs are supported for MikroTik address planning.")
    if interface.network.prefixlen < 8 or interface.network.prefixlen > 32:
        raise ConfigPlanError("Address prefix length must be between /8 and /32.")
    if not interface.ip.is_private:
        raise ConfigPlanError("Address must be private/local for this project policy.")
    return str(interface)


def _validate_mikrotik_dhcp_network(network: str) -> str:
    try:
        parsed = ipaddress.ip_network(network, strict=True)
    except ValueError as exc:
        raise ConfigPlanError("Network must be a valid IPv4 CIDR.") from exc
    if parsed.version != 4:
        raise ConfigPlanError("Only IPv4 DHCP networks are supported.")
    if not parsed.is_private:
        raise ConfigPlanError("DHCP network must be private/local for this project policy.")
    return str(parsed)


def _validate_gateway_in_network(gateway: str, network: str) -> str:
    try:
        gateway_ip = ipaddress.ip_address(gateway)
        parsed_network = ipaddress.ip_network(network)
    except ValueError as exc:
        raise ConfigPlanError("Gateway must be a valid IPv4 address.") from exc
    if gateway_ip.version != 4 or gateway_ip not in parsed_network:
        raise ConfigPlanError("Gateway must be an IPv4 address inside the DHCP network.")
    return str(gateway_ip)


def _validate_pool_range(pool_range: str, network: str) -> str:
    if "-" not in pool_range:
        raise ConfigPlanError("Pool range must use `<start_ip-end_ip>` format.")
    start_raw, end_raw = pool_range.split("-", 1)
    try:
        start = ipaddress.ip_address(start_raw.strip())
        end = ipaddress.ip_address(end_raw.strip())
        parsed_network = ipaddress.ip_network(network)
    except ValueError as exc:
        raise ConfigPlanError("Pool range must contain valid IPv4 addresses.") from exc
    if start.version != 4 or end.version != 4:
        raise ConfigPlanError("Pool range must contain IPv4 addresses.")
    if start not in parsed_network or end not in parsed_network:
        raise ConfigPlanError("Pool start and end must be inside the DHCP network.")
    if int(start) > int(end):
        raise ConfigPlanError("Pool start IP must be less than or equal to pool end IP.")
    return f"{start}-{end}"


def _validate_dns_servers(dns: str | None) -> str | None:
    if dns is None or not dns.strip():
        return None
    values = [item.strip() for item in dns.split(",") if item.strip()]
    if not values:
        return None
    normalized = []
    for value in values:
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ConfigPlanError(f"DNS server `{value}` is not a valid IP address.") from exc
        if parsed.version != 4:
            raise ConfigPlanError("Only IPv4 DNS servers are supported.")
        normalized.append(str(parsed))
    return ",".join(normalized)


def _validate_mikrotik_comment(comment: str | None) -> str | None:
    if comment is None or not comment.strip():
        return None
    value = " ".join(comment.strip().split())
    if len(value) > 64:
        raise ConfigPlanError("MikroTik comment must be 64 characters or fewer.")
    if MIKROTIK_COMMENT_UNSAFE.search(value):
        raise ConfigPlanError("MikroTik comment contains unsafe characters.")
    return value


def _validate_mikrotik_planning_commands(proposed: list[str], rollback: list[str]) -> None:
    commands = proposed + rollback
    for command in commands:
        lowered = command.lower().strip()
        for pattern in DESTRUCTIVE_MIKROTIK_PATTERNS:
            if pattern in lowered:
                raise ConfigPlanError(f"MikroTik planned command blocked: contains `{pattern}`.")
    for command in proposed:
        if not re.fullmatch(
            r'/ip address add address=[0-9.]+/\d{1,2} interface=[A-Za-z0-9_.\-/]+(?: comment="[^"\n\r;`|&$\[\]]{1,64}")?',
            command,
        ):
            raise ConfigPlanError(f"MikroTik proposed command is outside the allowed template: `{command}`.")
    for command in rollback:
        if not re.fullmatch(
            r'/ip address remove \[find address="[0-9.]+/\d{1,2}" interface="[A-Za-z0-9_.\-/]+"\]',
            command,
        ):
            raise ConfigPlanError(f"MikroTik rollback command is outside the allowed template: `{command}`.")


def _validate_mikrotik_dhcp_planning_commands(proposed: list[str], rollback: list[str]) -> None:
    for command in proposed + rollback:
        lowered = command.lower().strip()
        if any(char in command for char in (";", "\n", "\r", "`", "|", "&", "$")):
            raise ConfigPlanError("MikroTik DHCP command contains unsafe control characters.")
        for pattern in DESTRUCTIVE_MIKROTIK_PATTERNS:
            if pattern in lowered:
                raise ConfigPlanError(f"MikroTik DHCP planned command blocked: contains `{pattern}`.")
    parts = _mikrotik_dhcp_plan_parts_from_commands(proposed, rollback)
    if parts is None:
        raise ConfigPlanError("MikroTik DHCP commands are outside the allowed templates or rollback does not match proposed commands.")
    _validate_mikrotik_dhcp_network(parts.network)
    _validate_gateway_in_network(parts.gateway, parts.network)
    _validate_pool_range(parts.pool_range, parts.network)
    _validate_mikrotik_safe_name(parts.name, "DHCP server name")
    _validate_mikrotik_safe_name(parts.pool_name, "Pool name")
    _validate_mikrotik_interface(parts.interface)
    _validate_dns_servers(parts.dns)
    _validate_mikrotik_comment(parts.comment)


def _vlan_commands(vlan_id: int, name: str, ports: str | None) -> list[str]:
    commands = [f"vlan {vlan_id}", f" name {name}"]
    if ports:
        commands.extend(
            [
                f"interface range {ports}",
                " switchport mode access",
                f" switchport access vlan {vlan_id}",
                " spanning-tree portfast",
            ]
        )
    return commands


def _vlan_rollback(vlan_id: int, ports: str | None) -> list[str]:
    commands: list[str] = []
    if ports:
        commands.extend(
            [
                f"interface range {ports}",
                f" no switchport access vlan {vlan_id}",
                " no spanning-tree portfast",
            ]
        )
    commands.append(f"no vlan {vlan_id}")
    return commands


def _mikrotik_address_commands(address: str, interface: str, comment: str | None) -> list[str]:
    command = f"/ip address add address={address} interface={interface}"
    if comment:
        command += f' comment="{comment}"'
    return [command]


def _mikrotik_address_rollback(address: str, interface: str) -> list[str]:
    return [f'/ip address remove [find address="{address}" interface="{interface}"]']


def _mikrotik_dhcp_commands(
    name: str,
    interface: str,
    network: str,
    gateway: str,
    pool_name: str,
    pool_range: str,
    dns: str | None,
    comment: str | None,
) -> list[str]:
    server = f"/ip dhcp-server add name={name} interface={interface} address-pool={pool_name} disabled=no"
    if comment:
        server += f' comment="{comment}"'
    network_command = f"/ip dhcp-server network add address={network} gateway={gateway}"
    if dns:
        network_command += f" dns-server={dns}"
    return [
        f"/ip pool add name={pool_name} ranges={pool_range}",
        server,
        network_command,
    ]


def _mikrotik_dhcp_rollback(name: str, network: str, pool_name: str) -> list[str]:
    return [
        f'/ip dhcp-server remove [find name="{name}"]',
        f'/ip dhcp-server network remove [find address="{network}"]',
        f'/ip pool remove [find name="{pool_name}"]',
    ]


def _cisco_description_commands(interface: str, description: str) -> list[str]:
    return [f"interface {interface}", f" description {description}"]


def _cisco_description_rollback(interface: str) -> list[str]:
    return [f"interface {interface}", " no description"]


def _cisco_access_port_commands(interface: str, vlan_id: int, description: str | None) -> list[str]:
    commands = [
        f"interface {interface}",
        " switchport mode access",
        f" switchport access vlan {vlan_id}",
        " spanning-tree portfast",
    ]
    if description:
        commands.append(f" description {description}")
    return commands


def _cisco_access_port_rollback(interface: str, vlan_id: int, *, include_description: bool) -> list[str]:
    commands = [
        f"interface {interface}",
        f" no switchport access vlan {vlan_id}",
        " no spanning-tree portfast",
    ]
    if include_description:
        commands.append(" no description")
    return commands


def _description(device_ip: str, vlan_id: int, name: str, ports: str | None) -> str:
    if ports:
        return f"Plan only: create VLAN {vlan_id} named {name} on {device_ip} and assign access ports {ports}."
    return f"Plan only: create VLAN {vlan_id} named {name} on {device_ip}."


def _status_from_findings(findings: list[DiagnosticFinding]) -> str:
    if any(finding.severity == "high" for finding in findings):
        return "blocked"
    if any(finding.severity in {"medium", "low"} for finding in findings):
        return "draft"
    return "validated"


def _recent_successful_command_outputs(command_runs: list[CommandRun]) -> dict[str, str]:
    outputs: dict[str, str] = {}
    for run in sorted(command_runs, key=lambda item: item.started_at, reverse=True):
        if run.success and run.command not in outputs:
            outputs[run.command] = run.output
    return outputs


def _ports_may_overlap_trunks(ports: str, trunk_output: str) -> bool:
    tokens = re.findall(r"[A-Za-z]+\d+(?:/\d+){0,2}", ports)
    lowered = trunk_output.lower()
    return any(token.lower() in lowered for token in tokens)


def _interface_in_status_output(interface: str, status_output: str) -> bool:
    pattern = rf"(^|\s){re.escape(interface)}(\s|$)"
    return re.search(pattern, status_output, flags=re.IGNORECASE | re.MULTILINE) is not None


def _interface_in_trunk_output(interface: str, trunk_output: str) -> bool:
    pattern = rf"(^|\s){re.escape(interface)}(\s|$)"
    return re.search(pattern, trunk_output, flags=re.IGNORECASE | re.MULTILINE) is not None


def _routeros_name_in_output(name: str, output: str) -> bool:
    escaped = re.escape(name)
    return bool(
        re.search(rf'(^|\s)name="?{escaped}"?(\s|$)', output, flags=re.IGNORECASE | re.MULTILINE)
        or re.search(rf"(^|\s){escaped}(\s|$)", output, flags=re.IGNORECASE | re.MULTILINE)
    )


def _routeros_token_in_output(token: str, output: str) -> bool:
    escaped = re.escape(token)
    return re.search(rf'(^|\s|=)"?{escaped}"?(\s|$)', output, flags=re.IGNORECASE | re.MULTILINE) is not None
