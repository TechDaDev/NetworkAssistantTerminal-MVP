from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.database import drop_db, get_session, init_db
from app.models import Device, DeviceObservation, DevicePort, NetworkFact, ScanRun
from app.schemas import ScanResult


def save_scan_result(scan_result: ScanResult) -> None:
    init_db()
    now = datetime.now(timezone.utc)
    with get_session() as session:
        scan_run = ScanRun(
            interface_name=scan_result.network_info.interface_name,
            local_ip=scan_result.network_info.local_ip,
            cidr=scan_result.network_info.cidr,
            gateway_ip=scan_result.network_info.gateway_ip,
            started_at=scan_result.started_at,
            finished_at=scan_result.finished_at,
            live_hosts_count=scan_result.live_hosts_count,
            summary_json=json.dumps(
                {
                    "devices": [device.model_dump(mode="json") for device in scan_result.devices],
                    "network_info": scan_result.network_info.model_dump(mode="json"),
                }
            ),
        )
        session.add(scan_run)

        for scanned in scan_result.devices:
            device = session.scalar(
                select(Device).where(Device.ip_address == scanned.host.ip_address)
            )
            if device is None:
                device = Device(ip_address=scanned.host.ip_address, created_at=now)
                session.add(device)

            device.hostname = scanned.host.hostname
            device.mac_address = scanned.host.mac_address or device.mac_address
            device.vendor_guess = scanned.fingerprint.vendor_guess
            device.device_type_guess = scanned.fingerprint.type_guess
            device.confidence = scanned.fingerprint.confidence
            device.last_seen = now
            device.updated_at = now

            existing_ports = {(port.port, port.protocol): port for port in device.ports}
            scanned_port_keys = {
                (port_result.port, port_result.protocol) for port_result in scanned.ports
            }
            for key, device_port in list(existing_ports.items()):
                if key not in scanned_port_keys:
                    session.delete(device_port)

            for port_result in scanned.ports:
                key = (port_result.port, port_result.protocol)
                device_port = existing_ports.get(key)
                if device_port is None:
                    device_port = DevicePort(device=device, port=port_result.port, protocol=port_result.protocol)
                    session.add(device_port)
                device_port.service_guess = port_result.service_guess
                device_port.state = port_result.state
                device_port.last_seen = now

            for note in scanned.fingerprint.notes:
                session.add(
                    NetworkFact(
                        device=device,
                        fact_type="note",
                        fact_value=note,
                        confidence=scanned.fingerprint.confidence,
                        source="fingerprint",
                    )
                )

        session.commit()


def list_devices() -> list[Device]:
    init_db()
    with get_session() as session:
        devices = session.scalars(
            select(Device)
            .options(
                selectinload(Device.ports),
                selectinload(Device.facts),
                selectinload(Device.observations),
                selectinload(Device.credentials),
                selectinload(Device.command_runs),
            )
            .order_by(Device.ip_address)
        ).all()
        return list(devices)


def get_device_profile(ip_address: str) -> Device | None:
    init_db()
    with get_session() as session:
        return session.scalar(
            select(Device)
            .options(
                selectinload(Device.ports),
                selectinload(Device.facts),
                selectinload(Device.observations),
                selectinload(Device.credentials),
                selectinload(Device.command_runs),
            )
            .where(Device.ip_address == ip_address)
        )


def update_device_profile(
    ip_address: str,
    vendor: str | None = None,
    model: str | None = None,
    device_type: str | None = None,
) -> Device | None:
    init_db()
    now = datetime.now(timezone.utc)
    with get_session() as session:
        device = session.scalar(
            select(Device)
            .options(
                selectinload(Device.ports),
                selectinload(Device.observations),
                selectinload(Device.credentials),
                selectinload(Device.command_runs),
            )
            .where(Device.ip_address == ip_address)
        )
        if device is None:
            return None

        if vendor:
            device.vendor_guess = vendor
            device.observations.append(
                DeviceObservation(
                    observation_type="manual_vendor",
                    observation_value=vendor,
                    source="user",
                    confidence="High",
                )
            )
        if model:
            device.observations.append(
                DeviceObservation(
                    observation_type="manual_model",
                    observation_value=model,
                    source="user",
                    confidence="High",
                )
            )
        if device_type:
            device.device_type_guess = device_type
            device.observations.append(
                DeviceObservation(
                    observation_type="manual_device_type",
                    observation_value=device_type,
                    source="user",
                    confidence="High",
                )
            )
        if vendor or model or device_type:
            device.confidence = "High"
            device.updated_at = now
        session.commit()
        session.refresh(device)
        return device


def get_latest_scan_report() -> dict:
    init_db()
    with get_session() as session:
        latest = session.scalar(select(ScanRun).order_by(ScanRun.finished_at.desc()))
        if latest is None:
            return {}
        summary = json.loads(latest.summary_json or "{}")
        scan_ips = {
            device["host"]["ip_address"] for device in summary.get("devices", [])
        }
        inventory_devices = session.scalars(
            select(Device)
            .options(selectinload(Device.ports), selectinload(Device.observations))
            .where(Device.ip_address.in_(scan_ips))
        ).all() if scan_ips else []
        return {
            "scan": latest,
            "summary": summary,
            "devices": summary.get("devices", []),
            "network_info": summary.get("network_info", {}),
            "inventory_devices": list(inventory_devices),
        }


def reset_database() -> None:
    drop_db()
    init_db()
