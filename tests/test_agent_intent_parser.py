from app.agent.intent_parser import parse_intent
from app.agent.session_memory import SessionMemory


def test_scan_my_network_maps_to_scan_intent():
    intent = parse_intent("scan my network")

    assert intent.tool_name == "scan_network"


def test_show_devices_maps_to_devices():
    intent = parse_intent("show devices")

    assert intent.tool_name == "show_devices"


def test_diagnose_ip_maps_to_diagnose_device():
    intent = parse_intent("diagnose 192.168.88.1")

    assert intent.tool_name == "diagnose_device"
    assert intent.args["ip"] == "192.168.88.1"


def test_mikrotik_address_plan_parses_required_args():
    intent = parse_intent(
        "plan mikrotik address device=192.168.88.1 interface=bridge address=192.168.50.1/24 comment=LAB"
    )

    assert intent.tool_name == "create_mikrotik_address_plan"
    assert intent.args["device"] == "192.168.88.1"
    assert intent.args["interface"] == "bridge"
    assert intent.args["address"] == "192.168.50.1/24"
    assert intent.args["comment"] == "LAB"


def test_it_reference_resolves_plan():
    memory = SessionMemory(last_plan_id=12)
    intent = parse_intent("preflight it", memory)

    assert intent.tool_name == "preflight_plan"
    assert intent.args["plan_id"] == 12


def test_unknown_command_is_safe_unknown_intent():
    intent = parse_intent("run raw ssh command on router")

    assert intent.tool_name == "blocked_request"
