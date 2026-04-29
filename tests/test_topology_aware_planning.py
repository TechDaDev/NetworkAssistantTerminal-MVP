from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import Base, ChangePlan, Device, DeviceCredential, ManualTopologyNote
from app.services import config_planner, topology_awareness
from app.services.config_planner import create_mikrotik_dhcp_plan, run_preflight
from app.services.topology_awareness import analyze_plan_topology_risk


def _install_temp_db(monkeypatch):
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    monkeypatch.setattr(config_planner, "init_db", lambda: None)
    monkeypatch.setattr(config_planner, "get_session", session_local)
    monkeypatch.setattr(topology_awareness, "init_db", lambda: None)
    monkeypatch.setattr(topology_awareness, "get_session", session_local)
    return session_local


def _add_device(session_local, ip="192.168.88.1", vendor="MikroTik", device_type="Router") -> Device:
    now = datetime.now(timezone.utc)
    with session_local() as session:
        device = Device(
            ip_address=ip,
            vendor_guess=vendor,
            device_type_guess=device_type,
            confidence="High",
            last_seen=now,
        )
        device.credentials = [
            DeviceCredential(
                username="admin",
                encrypted_password="encrypted",
                connection_type="ssh",
                port=22,
                platform_hint="mikrotik_routeros",
                status="stored",
                created_at=now,
                updated_at=now,
            )
        ]
        session.add(device)
        session.commit()
        return device


def _dhcp_plan(device: Device, *, interface="bridge", pool_range="192.168.50.100-192.168.50.200") -> ChangePlan:
    return ChangePlan(
        id=1,
        device=device,
        plan_type="mikrotik_dhcp_server",
        title="DHCP",
        description="test",
        risk_level="medium",
        status="draft",
        proposed_commands=(
            f"/ip pool add name=lab-pool ranges={pool_range}\n"
            f"/ip dhcp-server add name=lab-dhcp interface={interface} address-pool=lab-pool disabled=no\n"
            "/ip dhcp-server network add address=192.168.50.0/24 gateway=192.168.50.1"
        ),
        rollback_commands=(
            '/ip dhcp-server remove [find name="lab-dhcp"]\n'
            '/ip dhcp-server network remove [find address="192.168.50.0/24"]\n'
            '/ip pool remove [find name="lab-pool"]'
        ),
    )


def test_missing_topology_gives_info_warning(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    device = _add_device(session_local)

    findings = analyze_plan_topology_risk(_dhcp_plan(device))

    assert any(finding.title == "No topology snapshot available" and finding.severity == "info" for finding in findings)


def test_dhcp_pool_overlap_with_known_device_warns(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    device = _add_device(session_local)
    _add_device(session_local, ip="192.168.50.120", vendor="Generic", device_type="Client")

    findings = analyze_plan_topology_risk(_dhcp_plan(device))

    assert any(finding.title == "DHCP pool overlaps known device IP" and finding.severity == "medium" for finding in findings)


def test_dhcp_pool_overlap_with_router_is_high(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    device = _add_device(session_local)
    _add_device(session_local, ip="192.168.50.1", vendor="MikroTik", device_type="Router")

    findings = analyze_plan_topology_risk(_dhcp_plan(device, pool_range="192.168.50.1-192.168.50.10"))

    assert any(finding.title == "DHCP pool overlaps known infrastructure IP" and finding.severity == "high" for finding in findings)


def test_uplink_interface_heuristic_warns_for_mikrotik_dhcp(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    device = _add_device(session_local)

    findings = analyze_plan_topology_risk(_dhcp_plan(device, interface="ether1"))

    assert any(finding.title == "Interface may be uplink/WAN" and finding.severity == "medium" for finding in findings)


def test_bridge_interface_does_not_high_warn(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    device = _add_device(session_local)

    findings = analyze_plan_topology_risk(_dhcp_plan(device, interface="bridge"))

    assert not any(finding.title == "Interface may be uplink/WAN" for finding in findings)


def test_manual_note_containing_uplink_warns_for_cisco_access_port(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    device = _add_device(session_local, ip="192.168.88.20", vendor="Cisco", device_type="Switch")
    with session_local() as session:
        session.add(ManualTopologyNote(target_type="node", target_key="device_192_168_88_20", note="Gi0/1 is uplink to router"))
        session.commit()
    plan = ChangePlan(
        id=2,
        device=device,
        plan_type="cisco_access_port",
        title="access",
        description="test",
        risk_level="medium",
        status="draft",
        proposed_commands="interface Gi0/1\n switchport mode access\n switchport access vlan 30\n spanning-tree portfast",
        rollback_commands="interface Gi0/1\n no switchport access vlan 30\n no spanning-tree portfast",
    )

    findings = analyze_plan_topology_risk(plan)

    assert any(finding.title == "Manual topology indicates infrastructure link" for finding in findings)


def test_do_not_modify_manual_note_fails_preflight(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    _add_device(session_local)
    result = create_mikrotik_dhcp_plan(
        device_ip="192.168.88.1",
        name="lab-dhcp",
        interface="bridge",
        network="192.168.50.0/24",
        gateway="192.168.50.1",
        pool_name="lab-pool",
        pool_range="192.168.50.100-192.168.50.200",
    )
    with session_local() as session:
        plan = session.get(ChangePlan, result.plan.id)
        plan.status = "approved"
        session.add(ManualTopologyNote(target_type="node", target_key="device_192_168_88_1", note="bridge do not modify"))
        session.commit()

    preflight = run_preflight(result.plan.id)

    assert preflight.plan.preflight_status == "failed"
    assert any(finding.title == "Manual topology note blocks change" for finding in preflight.findings)
