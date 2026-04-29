from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.config import BASE_DIR
from app.database import get_session, init_db
from app.models import ChangePlan, Device, DeviceConfigSnapshot, ExecutionLog
from app.services.device_connection import test_connection


LAB_ENV_KEYS = {
    "cisco": (
        "LAB_CISCO_IP",
        "LAB_CISCO_USERNAME",
        "LAB_CISCO_PASSWORD",
        "LAB_CISCO_PLATFORM",
        "LAB_CISCO_TEST_INTERFACE",
        "LAB_CISCO_TEST_VLAN",
        "LAB_CISCO_TEST_DESCRIPTION",
    ),
    "mikrotik": (
        "LAB_MIKROTIK_IP",
        "LAB_MIKROTIK_USERNAME",
        "LAB_MIKROTIK_PASSWORD",
        "LAB_MIKROTIK_PLATFORM",
        "LAB_MIKROTIK_TEST_INTERFACE",
        "LAB_MIKROTIK_TEST_ADDRESS",
        "LAB_MIKROTIK_DHCP_NAME",
        "LAB_MIKROTIK_DHCP_POOL_NAME",
        "LAB_MIKROTIK_DHCP_NETWORK",
        "LAB_MIKROTIK_DHCP_GATEWAY",
        "LAB_MIKROTIK_DHCP_POOL_RANGE",
        "LAB_MIKROTIK_DHCP_DNS",
    ),
}


@dataclass
class IntegrationCheck:
    name: str
    status: str
    detail: str
    recommendation: str | None = None


@dataclass
class IntegrationHarnessResult:
    title: str
    summary: str
    checks: list[IntegrationCheck] = field(default_factory=list)
    suggested_commands: list[str] = field(default_factory=list)


def integration_flags(env: dict[str, str] | None = None) -> dict[str, bool]:
    source = _env_source(env)
    return {
        "run_integration_tests": _env_bool(source.get("RUN_INTEGRATION_TESTS")),
        "allow_real_config_tests": _env_bool(source.get("ALLOW_REAL_CONFIG_TESTS")),
        "allow_real_dhcp_tests": _env_bool(source.get("ALLOW_REAL_DHCP_TESTS")),
    }


def real_config_enabled(env: dict[str, str] | None = None) -> bool:
    return integration_flags(env)["allow_real_config_tests"]


def real_dhcp_enabled(env: dict[str, str] | None = None) -> bool:
    flags = integration_flags(env)
    return flags["allow_real_config_tests"] and flags["allow_real_dhcp_tests"]


def integration_check(connect: bool = False, env: dict[str, str] | None = None) -> IntegrationHarnessResult:
    source = _env_source(env)
    flags = integration_flags(source)
    checks: list[IntegrationCheck] = [
        IntegrationCheck(
            "Integration tests enabled",
            "pass" if flags["run_integration_tests"] else "warning",
            f"RUN_INTEGRATION_TESTS={str(flags['run_integration_tests']).lower()}",
            "Set RUN_INTEGRATION_TESTS=true to run pytest integration tests." if not flags["run_integration_tests"] else None,
        ),
        IntegrationCheck(
            "Real config tests",
            "warning" if flags["allow_real_config_tests"] else "info",
            f"ALLOW_REAL_CONFIG_TESTS={str(flags['allow_real_config_tests']).lower()}",
            "Enable only in an isolated CHR/IOSv lab." if flags["allow_real_config_tests"] else None,
        ),
        IntegrationCheck(
            "Real DHCP tests",
            "warning" if flags["allow_real_dhcp_tests"] else "info",
            f"ALLOW_REAL_DHCP_TESTS={str(flags['allow_real_dhcp_tests']).lower()}",
            "DHCP execution also requires ALLOW_REAL_CONFIG_TESTS=true." if flags["allow_real_dhcp_tests"] else None,
        ),
    ]
    checks.extend(_device_env_checks("Cisco", LAB_ENV_KEYS["cisco"], source))
    checks.extend(_device_env_checks("MikroTik", LAB_ENV_KEYS["mikrotik"], source))
    if connect:
        checks.extend(_connectivity_checks(source))
    else:
        checks.append(
            IntegrationCheck(
                "SSH connectivity",
                "info",
                "Not checked. `--connect` was not used, so no network connection was attempted.",
                "python main.py lab integration-check --connect",
            )
        )
    return IntegrationHarnessResult(
        title="Lab Integration Check",
        summary=_summary(checks),
        checks=checks,
        suggested_commands=[
            "pytest",
            "pytest -m integration",
            "RUN_INTEGRATION_TESTS=true pytest -m integration",
            "RUN_INTEGRATION_TESTS=true ALLOW_REAL_CONFIG_TESTS=true pytest -m integration",
        ],
    )


def integration_report(env: dict[str, str] | None = None) -> IntegrationHarnessResult:
    source = _env_source(env)
    init_db()
    checks: list[IntegrationCheck] = []
    with get_session() as session:
        for label, ip_key in (("Cisco", "LAB_CISCO_IP"), ("MikroTik", "LAB_MIKROTIK_IP")):
            ip = source.get(ip_key, "").strip()
            if not ip:
                checks.append(IntegrationCheck(f"{label} lab device", "warning", f"{ip_key} is not configured."))
                continue
            device = session.scalar(
                select(Device)
                .options(selectinload(Device.change_plans), selectinload(Device.execution_logs), selectinload(Device.config_snapshots))
                .where(Device.ip_address == ip)
            )
            if device is None:
                checks.append(IntegrationCheck(f"{label} inventory", "warning", f"{ip} is not in inventory.", "python main.py scan"))
                continue
            plans = len(device.change_plans)
            executions = len(device.execution_logs)
            snapshots = len(device.config_snapshots)
            latest_log = _latest_execution(device.execution_logs)
            checks.append(
                IntegrationCheck(
                    f"{label} lab records",
                    "info",
                    f"{ip}: plans={plans}, execution_logs={executions}, snapshots={snapshots}, latest_execution={latest_log.status if latest_log else 'none'}",
                )
            )
    return IntegrationHarnessResult(
        title="Lab Integration Report",
        summary=_summary(checks),
        checks=checks,
        suggested_commands=[
            "python main.py lab integration-check",
            "python main.py lab validate-device <ip>",
            "python main.py snapshot list --device <ip>",
        ],
    )


def integration_env_ready(vendor: str, env: dict[str, str] | None = None) -> tuple[bool, list[str]]:
    source = _env_source(env)
    missing = [key for key in LAB_ENV_KEYS[vendor] if not source.get(key, "").strip()]
    return not missing, missing


def integration_env_value(key: str, default: str = "") -> str:
    return _env_source().get(key, default)


def upsert_lab_device(ip_address: str, vendor_guess: str, device_type_guess: str) -> Device:
    init_db()
    now = datetime.now(timezone.utc)
    with get_session() as session:
        device = session.scalar(select(Device).where(Device.ip_address == ip_address))
        if device is None:
            device = Device(
                ip_address=ip_address,
                vendor_guess=vendor_guess,
                device_type_guess=device_type_guess,
                confidence="High",
                last_seen=now,
                created_at=now,
                updated_at=now,
            )
            session.add(device)
        else:
            device.vendor_guess = vendor_guess
            device.device_type_guess = device_type_guess
            device.confidence = "High"
            device.last_seen = now
            device.updated_at = now
        session.commit()
        session.refresh(device)
        return device


def redact_integration_env(env: dict[str, str] | None = None) -> dict[str, str]:
    source = _env_source(env)
    keys = {"RUN_INTEGRATION_TESTS", "ALLOW_REAL_CONFIG_TESTS", "ALLOW_REAL_DHCP_TESTS"}
    for values in LAB_ENV_KEYS.values():
        keys.update(values)
    redacted: dict[str, str] = {}
    for key in sorted(keys):
        value = source.get(key, "")
        redacted[key] = "***REDACTED***" if "PASSWORD" in key and value else value
    return redacted


def _device_env_checks(label: str, keys: tuple[str, ...], env: dict[str, str]) -> list[IntegrationCheck]:
    checks: list[IntegrationCheck] = []
    missing = [key for key in keys if not env.get(key, "").strip()]
    if missing:
        checks.append(
            IntegrationCheck(
                f"{label} environment",
                "warning",
                f"Missing: {', '.join(missing)}",
                "Populate .env or shell environment before running integration tests.",
            )
        )
    else:
        checks.append(IntegrationCheck(f"{label} environment", "pass", "Required lab environment variables are present."))
    password_keys = [key for key in keys if "PASSWORD" in key]
    for key in password_keys:
        if env.get(key):
            checks.append(IntegrationCheck(f"{label} {key}", "info", f"{key}=***REDACTED***"))
    return checks


def _connectivity_checks(env: dict[str, str]) -> list[IntegrationCheck]:
    checks: list[IntegrationCheck] = []
    for label, ip_key in (("Cisco", "LAB_CISCO_IP"), ("MikroTik", "LAB_MIKROTIK_IP")):
        ip = env.get(ip_key, "").strip()
        if not ip:
            checks.append(IntegrationCheck(f"{label} SSH", "warning", f"{ip_key} is not configured."))
            continue
        try:
            result = test_connection(ip)
        except Exception as exc:
            checks.append(IntegrationCheck(f"{label} SSH", "fail", str(exc)))
            continue
        checks.append(
            IntegrationCheck(
                f"{label} SSH",
                "pass" if result.success else "fail",
                f"{ip}: {result.message}",
                None if result.success else f"python main.py credentials add {ip}",
            )
        )
    return checks


def _latest_execution(logs: list[ExecutionLog]) -> ExecutionLog | None:
    if not logs:
        return None
    return max(logs, key=lambda item: item.started_at or datetime.min.replace(tzinfo=timezone.utc))


def _env_bool(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _env_source(env: dict[str, str] | None = None) -> dict[str, str]:
    if env is not None:
        return env
    values: dict[str, str] = {}
    try:
        from dotenv import dotenv_values

        values.update({key: str(value) for key, value in dotenv_values(BASE_DIR / ".env").items() if value is not None})
    except Exception:
        pass
    values.update(os.environ)
    return values


def _summary(checks: list[IntegrationCheck]) -> str:
    failed = sum(1 for check in checks if check.status == "fail")
    warnings = sum(1 for check in checks if check.status == "warning")
    passed = sum(1 for check in checks if check.status == "pass")
    return f"Integration harness status: pass={passed}, warning={warnings}, fail={failed}."
