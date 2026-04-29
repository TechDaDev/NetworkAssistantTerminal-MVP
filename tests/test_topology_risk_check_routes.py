from app import server
from app.agent.intent_parser import parse_intent
from app.agent.policy import evaluate_agent_action
from app.models import ChangePlan, Device
from app.schemas import DiagnosticFinding
from app.services.command_router import route_local_command


def _plan() -> ChangePlan:
    device = Device(id=1, ip_address="192.168.88.1", vendor_guess="MikroTik", device_type_guess="Router")
    return ChangePlan(
        id=25,
        device=device,
        plan_type="mikrotik_dhcp_server",
        title="DHCP",
        description="test",
        risk_level="medium",
        status="draft",
        proposed_commands="/ip pool add name=lab-pool ranges=192.168.50.100-192.168.50.200",
        rollback_commands='/ip pool remove [find name="lab-pool"]',
    )


def test_server_topology_risk_check_endpoint(monkeypatch):
    monkeypatch.setattr(server, "get_change_plan", lambda plan_id: _plan() if plan_id == 25 else None)
    monkeypatch.setattr(
        server,
        "analyze_plan_topology_risk",
        lambda _plan: [DiagnosticFinding(severity="info", title="No topology snapshot available", detail="missing")],
    )

    response = server.topology_risk_check_endpoint(25)

    assert response["ok"] is True
    assert response["findings"][0]["title"] == "No topology snapshot available"


def test_chat_router_topology_risk_check_route(monkeypatch):
    monkeypatch.setattr("app.services.command_router.get_change_plan", lambda plan_id: _plan() if plan_id == 25 else None)
    monkeypatch.setattr(
        "app.services.command_router.analyze_plan_topology_risk",
        lambda _plan: [DiagnosticFinding(severity="medium", title="Interface may be uplink/WAN", detail="ether1")],
    )

    result = route_local_command("topology risk check plan 25")

    assert result.ok
    assert result.data["findings"][0]["title"] == "Interface may be uplink/WAN"


def test_agent_parses_topology_risk_check_route():
    intent = parse_intent("risk check plan 25")
    decision = evaluate_agent_action(intent.tool_name, intent.args)

    assert intent.tool_name == "topology_risk_check"
    assert intent.args["plan_id"] == 25
    assert decision.allowed
    assert decision.risk_level == "low"
