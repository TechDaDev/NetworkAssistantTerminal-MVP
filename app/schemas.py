from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class NetworkInfo(BaseModel):
    interface_name: str
    local_ip: str
    netmask: str
    cidr: str
    gateway_ip: str | None = None
    mac_address: str | None = None
    is_private: bool
    prefix_length: int
    safe_to_scan: bool


class HostDiscoveryResult(BaseModel):
    ip_address: str
    mac_address: str | None = None
    hostname: str | None = None


class PortScanResult(BaseModel):
    port: int
    protocol: str = "tcp"
    service_guess: str
    state: str = "open"


class DeviceFingerprint(BaseModel):
    vendor_guess: str = "Unknown"
    type_guess: str = "Unknown"
    confidence: str = "Low"
    notes: list[str] = Field(default_factory=list)


class ScannedDevice(BaseModel):
    host: HostDiscoveryResult
    ports: list[PortScanResult] = Field(default_factory=list)
    fingerprint: DeviceFingerprint


class ScanResult(BaseModel):
    network_info: NetworkInfo
    devices: list[ScannedDevice]
    started_at: datetime
    finished_at: datetime

    @property
    def live_hosts_count(self) -> int:
        return len(self.devices)


class DiagnosticFinding(BaseModel):
    severity: str
    title: str
    detail: str
    evidence: list[str] = Field(default_factory=list)
    recommendation: str | None = None


class DiagnosticResult(BaseModel):
    title: str
    summary: str
    findings: list[DiagnosticFinding] = Field(default_factory=list)
    suggested_commands: list[str] = Field(default_factory=list)
