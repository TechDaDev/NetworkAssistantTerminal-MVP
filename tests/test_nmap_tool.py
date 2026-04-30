from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import Base, Device
from app.services import nmap_tool
from app.services.nmap_tool import parse_nmap_xml, save_nmap_results


SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.88.1" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
    <hostnames><hostname name="router.local"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6"/></port>
      <port protocol="tcp" portid="80"><state state="closed"/><service name="http"/></port>
      <port protocol="tcp" portid="8291"><state state="open"/><service name="winbox"/></port>
    </ports>
  </host>
</nmaprun>
"""


def _install_temp_db(monkeypatch):
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    monkeypatch.setattr(nmap_tool, "init_db", lambda: None)
    monkeypatch.setattr(nmap_tool, "get_session", session_local)
    return session_local


def test_nmap_missing_returns_unavailable(monkeypatch):
    monkeypatch.setattr(nmap_tool.shutil, "which", lambda _name: None)

    assert nmap_tool.is_nmap_available() is False
    assert nmap_tool.get_nmap_version() is None


def test_nmap_version_parsing(monkeypatch):
    class Completed:
        stdout = "Nmap version 7.94 ( https://nmap.org )\nPlatform details"
        stderr = ""

    monkeypatch.setattr(nmap_tool.shutil, "which", lambda _name: "/usr/bin/nmap")
    monkeypatch.setattr(nmap_tool.subprocess, "run", lambda *_args, **_kwargs: Completed())

    assert nmap_tool.get_nmap_version() == "Nmap version 7.94 ( https://nmap.org )"


def test_xml_parsing_extracts_hosts_ports_and_services():
    result = parse_nmap_xml(SAMPLE_XML)

    assert result.live_hosts_count == 1
    device = result.devices[0]
    assert device.host.ip_address == "192.168.88.1"
    assert device.host.hostname == "router.local"
    assert [port.port for port in device.ports] == [22, 8291]
    assert device.ports[0].service_guess == "ssh OpenSSH 9.6"


def test_save_results_updates_inventory_and_ports(monkeypatch):
    session_local = _install_temp_db(monkeypatch)
    result = parse_nmap_xml(SAMPLE_XML)
    result.target = "192.168.88.1"
    result.profile = "service-light"
    result.started_at = datetime.now(timezone.utc)
    result.finished_at = datetime.now(timezone.utc)

    save_nmap_results(result)

    with session_local() as session:
        device = session.query(Device).filter(Device.ip_address == "192.168.88.1").one()
        ports = sorted(port.port for port in device.ports)
        assert device.hostname == "router.local"
        assert ports == [22, 8291]
