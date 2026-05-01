from types import SimpleNamespace

from app.services import network_fact


class _Port:
    def __init__(self, port: int) -> None:
        self.port = port


def test_answer_network_fact_returns_vendor_when_gateway_in_inventory(monkeypatch):
    monkeypatch.setattr(
        network_fact,
        "detect_local_network",
        lambda: SimpleNamespace(
            local_ip="192.168.88.10",
            interface_name="eth0",
            cidr="192.168.88.0/24",
            gateway_ip="192.168.88.1",
        ),
    )
    monkeypatch.setattr(
        network_fact,
        "get_device_profile",
        lambda _ip: SimpleNamespace(
            vendor_guess="MikroTik",
            device_type_guess="router",
            ports=[_Port(22), _Port(8291)],
        ),
    )

    result = network_fact.answer_network_fact("what is the vendor of the network gateway?")

    assert result.gateway_ip == "192.168.88.1"
    assert result.vendor == "MikroTik"
    assert result.device_type == "router"
    assert result.open_ports == [22, 8291]
    assert result.in_inventory is True
    assert result.suggest_scan is False


def test_answer_network_fact_returns_gateway_even_when_inventory_missing(monkeypatch):
    monkeypatch.setattr(
        network_fact,
        "detect_local_network",
        lambda: SimpleNamespace(
            local_ip="192.168.88.10",
            interface_name="eth0",
            cidr="192.168.88.0/24",
            gateway_ip="192.168.88.1",
        ),
    )
    monkeypatch.setattr(network_fact, "get_device_profile", lambda _ip: None)

    result = network_fact.answer_network_fact("what is the gateway ip")

    assert result.gateway_ip == "192.168.88.1"
    assert result.in_inventory is False
    assert result.suggest_scan is True
    assert result.note is not None
    assert "scan/enrich" in result.note.lower()


def test_answer_network_fact_includes_network_and_local_ip(monkeypatch):
    monkeypatch.setattr(
        network_fact,
        "detect_local_network",
        lambda: SimpleNamespace(
            local_ip="10.0.0.50",
            interface_name="wlan0",
            cidr="10.0.0.0/24",
            gateway_ip="10.0.0.1",
        ),
    )
    monkeypatch.setattr(network_fact, "get_device_profile", lambda _ip: None)

    result = network_fact.answer_network_fact("what subnet am i connected to")

    assert result.local_ip == "10.0.0.50"
    assert result.interface == "wlan0"
    assert result.cidr == "10.0.0.0/24"
    assert result.network == "10.0.0.0/24"


def test_port_question_without_inventory_ports_suggests_scan_or_nmap(monkeypatch):
    monkeypatch.setattr(
        network_fact,
        "detect_local_network",
        lambda: SimpleNamespace(
            local_ip="192.168.88.10",
            interface_name="eth0",
            cidr="192.168.88.0/24",
            gateway_ip="192.168.88.1",
        ),
    )
    monkeypatch.setattr(network_fact, "get_device_profile", lambda _ip: None)

    result = network_fact.answer_network_fact("what ports are open on the gateway")

    assert result.note is not None
    assert "nmap scan" in result.note.lower() or "scan my network" in result.note.lower()
