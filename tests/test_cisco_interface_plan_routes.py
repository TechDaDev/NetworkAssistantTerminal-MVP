from app import server
from app.models import ChangePlan, Device
from app.services.command_router import route_local_command
from app.services.config_planner import ChangePlanResult


def _plan(plan_type: str = "cisco_interface_description") -> ChangePlan:
    device = Device(id=1, ip_address="192.168.88.20", vendor_guess="Cisco", device_type_guess="Switch")
    return ChangePlan(
        id=9,
        device=device,
        plan_type=plan_type,
        title="Cisco interface plan",
        description="test",
        risk_level="low",
        status="draft",
        proposed_commands="interface Gi0/5\n description LAB-PC-01",
        rollback_commands="interface Gi0/5\n no description",
        validation_findings="[]",
    )


def test_server_cisco_description_endpoint(monkeypatch):
    monkeypatch.setattr(server, "create_cisco_description_plan", lambda **_kwargs: ChangePlanResult(_plan(), []))

    response = server.plan_cisco_description_endpoint(
        server.CiscoDescriptionPlanRequest(device="192.168.88.20", interface="Gi0/5", description="LAB-PC-01")
    )

    assert response["ok"] is True
    assert response["plan"]["plan_type"] == "cisco_interface_description"


def test_server_cisco_access_port_endpoint(monkeypatch):
    monkeypatch.setattr(server, "create_cisco_access_port_plan", lambda **_kwargs: ChangePlanResult(_plan("cisco_access_port"), []))

    response = server.plan_cisco_access_port_endpoint(
        server.CiscoAccessPortPlanRequest(device="192.168.88.20", interface="Gi0/5", vlan_id=30, description="LAB-PC-01")
    )

    assert response["ok"] is True
    assert response["plan"]["plan_type"] == "cisco_access_port"


def test_chat_router_cisco_description_route(monkeypatch):
    monkeypatch.setattr("app.services.command_router.create_cisco_description_plan", lambda **_kwargs: ChangePlanResult(_plan(), []))

    result = route_local_command("plan cisco description device=192.168.88.20 interface=Gi0/5 description=LAB-PC-01")

    assert result.ok
    assert result.data["plan_type"] == "cisco_interface_description"


def test_chat_router_cisco_access_port_route(monkeypatch):
    monkeypatch.setattr("app.services.command_router.create_cisco_access_port_plan", lambda **_kwargs: ChangePlanResult(_plan("cisco_access_port"), []))

    result = route_local_command("plan cisco access-port device=192.168.88.20 interface=Gi0/5 vlan=30 description=LAB-PC-01")

    assert result.ok
    assert result.data["plan_type"] == "cisco_access_port"
