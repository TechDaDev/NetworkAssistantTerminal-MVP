from app import server
from app.models import ChangePlan, Device
from app.services.command_router import route_local_command
from app.services.config_planner import ChangePlanResult


def _plan() -> ChangePlan:
    device = Device(id=1, ip_address="192.168.88.1", vendor_guess="MikroTik", device_type_guess="Router")
    return ChangePlan(
        id=23,
        device=device,
        plan_type="mikrotik_dhcp_server",
        title="MikroTik DHCP plan",
        description="test",
        risk_level="medium",
        status="draft",
        proposed_commands="/ip pool add name=lab-pool ranges=192.168.50.100-192.168.50.200",
        rollback_commands='/ip pool remove [find name="lab-pool"]',
        validation_findings="[]",
    )


def test_server_mikrotik_dhcp_endpoint(monkeypatch):
    monkeypatch.setattr(server, "create_mikrotik_dhcp_plan", lambda **_kwargs: ChangePlanResult(_plan(), []))

    response = server.plan_mikrotik_dhcp_endpoint(
        server.MikroTikDhcpPlanRequest(
            device="192.168.88.1",
            name="lab-dhcp",
            interface="bridge",
            network="192.168.50.0/24",
            gateway="192.168.50.1",
            pool_name="lab-pool",
            pool_range="192.168.50.100-192.168.50.200",
            dns="8.8.8.8,1.1.1.1",
            comment="LAB DHCP",
        )
    )

    assert response["ok"] is True
    assert response["plan"]["plan_type"] == "mikrotik_dhcp_server"
    assert "MIKROTIK DHCP EXECUTION IS NOT SUPPORTED YET" in response["warning"]


def test_chat_router_mikrotik_dhcp_route(monkeypatch):
    monkeypatch.setattr("app.services.command_router.create_mikrotik_dhcp_plan", lambda **_kwargs: ChangePlanResult(_plan(), []))

    result = route_local_command(
        "plan mikrotik dhcp device=192.168.88.1 name=lab-dhcp interface=bridge "
        "network=192.168.50.0/24 gateway=192.168.50.1 pool-name=lab-pool "
        "pool-range=192.168.50.100-192.168.50.200 dns=8.8.8.8,1.1.1.1 comment='LAB DHCP'"
    )

    assert result.ok
    assert result.data["plan_type"] == "mikrotik_dhcp_server"


def test_chat_router_mikrotik_dhcp_requires_values():
    result = route_local_command("plan mikrotik dhcp device=192.168.88.1")

    assert not result.ok
    assert "Missing required values" in result.message
