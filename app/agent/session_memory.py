from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SessionMemory:
    last_device_ip: str | None = None
    last_plan_id: int | None = None
    last_scan_summary: str | None = None
    last_diagnostic_target: str | None = None
    last_knowledge_query: str | None = None

    def resolve_device(self, value: str | None) -> str | None:
        if value and value.lower() in {"it", "that device", "last device"}:
            return self.last_device_ip
        return value

    def resolve_plan(self, value: str | int | None) -> int | None:
        if isinstance(value, int):
            return value
        if value is None:
            return None
        if value.lower() in {"it", "that plan", "last plan"}:
            return self.last_plan_id
        if value.isdigit():
            return int(value)
        return None
