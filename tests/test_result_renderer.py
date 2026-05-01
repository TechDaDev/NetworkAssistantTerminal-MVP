from io import StringIO

from rich.console import Console

from app.agent.agent_models import AgentResult
from app.agent import result_renderer


def _capture_output(result: AgentResult, trace: bool = False) -> str:
    stream = StringIO()
    old_console = result_renderer.console
    old_trace = result_renderer.is_trace_enabled()
    result_renderer.console = Console(file=stream, force_terminal=False, width=140)
    result_renderer.set_trace(trace)
    try:
        result_renderer.print_result(result)
        return stream.getvalue()
    finally:
        result_renderer.set_trace(old_trace)
        result_renderer.console = old_console


def test_scan_result_renders_table_without_raw_json():
    result = AgentResult(
        action="scan_network",
        risk_level="medium",
        ok=True,
        message="scan complete",
        data={
            "network": "192.168.88.0/24",
            "live_hosts": 2,
            "devices": [
                {"ip": "192.168.88.1", "vendor": "MikroTik", "type": "router", "ports": [22, 80]},
                {"ip": "192.168.88.20", "vendor": "Cisco", "type": "switch", "ports": []},
            ],
        },
    )

    output = _capture_output(result)

    assert "Discovered Devices" in output
    assert "192.168.88.1" in output
    assert "MikroTik" in output
    assert "--" in output
    assert "Raw tool details" not in output


def test_devices_list_renders_inventory_table():
    result = AgentResult(
        action="show_devices",
        risk_level="low",
        ok=True,
        message="ok",
        data=[{"ip": "192.168.88.1", "vendor": "MikroTik", "type": "router", "ports": [22]}],
    )

    output = _capture_output(result)

    assert "Inventory Devices" in output
    assert "192.168.88.1" in output


def test_nmap_result_renders_nmap_table():
    result = AgentResult(
        action="nmap_scan_host",
        risk_level="medium",
        ok=True,
        message="ok",
        data={
            "target": "192.168.88.1",
            "profile": "common-ports",
            "live_hosts_count": 1,
            "devices": [
                {
                    "ip_address": "192.168.88.1",
                    "ports": [
                        {
                            "port": 22,
                            "protocol": "tcp",
                            "state": "open",
                            "service_name": "ssh",
                            "product": "dropbear",
                        }
                    ],
                }
            ],
        },
    )

    output = _capture_output(result)

    assert "Nmap Scan" in output
    assert "Nmap Results" in output
    assert "ssh" in output


def test_unknown_result_does_not_dump_raw_details_by_default():
    result = AgentResult(
        action="unknown_action",
        risk_level="low",
        ok=False,
        message="Unknown request",
        data={"relevant_tools": ["answer_network_fact"], "relevant_skills": ["diagnostics"]},
    )

    output = _capture_output(result)

    assert "Raw tool details" not in output
    assert "relevant_tools" not in output


def test_trace_mode_shows_raw_details():
    result = AgentResult(
        action="unknown_action",
        risk_level="low",
        ok=False,
        message="Unknown request",
        data={"relevant_tools": ["answer_network_fact"], "foo": "bar"},
    )

    output = _capture_output(result, trace=True)

    assert "Raw tool details" in output
    assert "relevant_tools" in output
    assert "foo" in output
