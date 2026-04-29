from datetime import datetime, timezone

from app.models import CommandRun, Device, DevicePort, ScanRun


def fake_scan() -> ScanRun:
    now = datetime.now(timezone.utc)
    return ScanRun(
        interface_name="eth0",
        local_ip="192.168.88.30",
        cidr="192.168.88.0/24",
        gateway_ip="192.168.88.1",
        started_at=now,
        finished_at=now,
        live_hosts_count=2,
        summary_json='{"network_info": {"safe_to_scan": true}, "devices": []}',
    )


def fake_devices() -> list[Device]:
    now = datetime.now(timezone.utc)
    gateway = Device(
        id=1,
        ip_address="192.168.88.1",
        mac_address="AA:AA:AA:AA:AA:AA",
        vendor_guess="MikroTik",
        device_type_guess="Router",
        confidence="High",
    )
    gateway.ports = [DevicePort(port=22, protocol="tcp", service_guess="SSH", state="open")]
    gateway.command_runs = [
        CommandRun(
            command="/ip arp print",
            output="0 192.168.88.20 BB:BB:BB:BB:BB:BB bridge\n1 192.168.88.77 CC:CC:CC:CC:CC:CC bridge",
            success=True,
            started_at=now,
            finished_at=now,
        )
    ]
    switch = Device(
        id=2,
        ip_address="192.168.88.20",
        mac_address="BB:BB:BB:BB:BB:BB",
        vendor_guess="Cisco",
        device_type_guess="Switch",
        confidence="High",
    )
    switch.ports = []
    switch.command_runs = [
        CommandRun(
            command="show cdp neighbors detail",
            output=(
                "Device ID: Core-Router\n"
                "IP address: 192.168.88.1\n"
                "Platform: cisco ISR, Capabilities: Router\n"
                "Interface: GigabitEthernet0/1,  Port ID (outgoing port): GigabitEthernet0/0"
            ),
            success=True,
            started_at=now,
            finished_at=now,
        )
    ]
    return [gateway, switch]
