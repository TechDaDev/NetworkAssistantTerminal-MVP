from datetime import datetime, timezone

from app.models import CommandRun, Device, DeviceCredential
from app.services.config_planner import validate_mikrotik_address_plan, validate_vlan_plan


def test_cisco_vlan_planner_uses_stored_evidence():
    now = datetime.now(timezone.utc)
    device = Device(
        ip_address="192.168.88.20",
        vendor_guess="Cisco",
        device_type_guess="Switch",
        confidence="High",
    )
    device.command_runs = [
        CommandRun(command="show vlan brief", output="1 default active", success=True, started_at=now, finished_at=now),
        CommandRun(command="show interfaces status", output="Gi0/5 connected", success=True, started_at=now, finished_at=now),
        CommandRun(command="show interfaces trunk", output="", success=True, started_at=now, finished_at=now),
    ]

    findings = validate_vlan_plan(device, vlan_id=30, name="LAB", ports="Gi0/5")

    assert any(finding.title == "VLAN not found in stored VLAN output" for finding in findings)
    assert not any(finding.severity == "high" for finding in findings)


def test_mikrotik_address_planner_warns_when_address_exists():
    now = datetime.now(timezone.utc)
    device = Device(
        ip_address="192.168.88.10",
        vendor_guess="MikroTik",
        device_type_guess="Router",
        confidence="High",
    )
    device.credentials = [
        DeviceCredential(username="admin", encrypted_password="encrypted", platform_hint="mikrotik_routeros")
    ]
    device.command_runs = [
        CommandRun(command="/interface print", output="0 R name=bridge", success=True, started_at=now, finished_at=now),
        CommandRun(command="/ip address print", output="0 192.168.50.1/24 192.168.50.0 bridge", success=True, started_at=now, finished_at=now),
    ]

    findings = validate_mikrotik_address_plan(device, interface="bridge", address="192.168.50.1/24")

    assert any(finding.title == "Address may already exist" for finding in findings)
