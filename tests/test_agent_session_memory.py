from app.agent.intent_parser import parse_intent
from app.agent.session_memory import SessionMemory


def test_that_device_resolves_to_last_device():
    memory = SessionMemory(last_device_ip="192.168.88.1")

    intent = parse_intent("diagnose that device", memory)

    assert intent.tool_name == "diagnose_device"
    assert intent.args["ip"] == "192.168.88.1"


def test_last_device_resolves_to_last_device():
    memory = SessionMemory(last_device_ip="192.168.88.20")

    intent = parse_intent("show last device", memory)

    assert intent.tool_name == "show_device"
    assert intent.args["ip"] == "192.168.88.20"


def test_that_plan_resolves_to_last_plan():
    memory = SessionMemory(last_plan_id=12)

    intent = parse_intent("preflight that plan", memory)

    assert intent.tool_name == "preflight_plan"
    assert intent.args["plan_id"] == 12


def test_show_last_plan_resolves_to_last_plan():
    memory = SessionMemory(last_plan_id=15)

    intent = parse_intent("show last plan", memory)

    assert intent.tool_name == "show_plan"
    assert intent.args["plan_id"] == 15
