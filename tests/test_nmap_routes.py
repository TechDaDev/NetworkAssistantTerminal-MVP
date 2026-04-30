import pytest
from fastapi import HTTPException

from app.release import doctor
from app import server
from app.services.command_router import route_local_command


def test_chat_router_nmap_check(monkeypatch):
    monkeypatch.setattr("app.services.command_router.is_nmap_available", lambda: True)
    monkeypatch.setattr("app.services.command_router.get_nmap_version", lambda: "Nmap version 7.94")

    result = route_local_command("nmap check")

    assert result.ok is True
    assert result.kind == "nmap"
    assert result.data["available"] is True


def test_chat_router_nmap_scan_host(monkeypatch):
    class Result:
        target = "192.168.88.1"
        profile = "common-ports"
        devices = []
        live_hosts_count = 0

    monkeypatch.setattr("app.services.command_router.run_nmap_scan", lambda target, profile: Result())
    monkeypatch.setattr("app.services.command_router.save_nmap_results", lambda result: None)

    result = route_local_command("nmap scan 192.168.88.1")

    assert result.ok is True
    assert result.data["target"] == "192.168.88.1"


def test_server_endpoint_rejects_public_target():
    with pytest.raises(HTTPException) as exc_info:
        server.nmap_scan_host_endpoint(server.NmapScanTargetRequest(target="8.8.8.8", profile="common-ports"))

    assert exc_info.value.status_code == 400
    assert "Public targets are blocked" in exc_info.value.detail


def test_doctor_reports_nmap_pass_when_present(monkeypatch):
    monkeypatch.setattr("app.release.shutil.which", lambda name: "/usr/bin/nmap" if name == "nmap" else None)
    monkeypatch.setattr("app.release.get_nmap_version", lambda: "Nmap version 7.94")

    result = doctor()
    nmap = next(check for check in result.checks if check.name == "nmap")

    assert nmap.status == "pass"
    assert "Nmap version 7.94" in nmap.detail


def test_doctor_warns_when_nmap_missing(monkeypatch):
    monkeypatch.setattr("app.release.shutil.which", lambda _name: None)

    result = doctor()
    nmap = next(check for check in result.checks if check.name == "nmap")

    assert nmap.status == "warning"
    assert nmap.recommendation == "sudo apt install nmap"
