from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.database import get_session, init_db
from app.models import ChangePlan, CommandRun, Device, DeviceCredential
from app.services.config_executor import ConfigExecutionError, execute_change_plan


SUPPORTED_LAB_PLATFORMS = {"cisco_ios", "mikrotik_routeros"}
SUPPORTED_PLAN_TYPES = {"vlan", "mikrotik_address"}

REQUIRED_EVIDENCE = {
    "cisco_ios": ("show vlan brief", "show interfaces status", "show interfaces trunk"),
    "mikrotik_routeros": ("/interface print", "/ip address print"),
}


@dataclass
class LabCheck:
    name: str
    status: str
    detail: str
    recommendation: str | None = None


@dataclass
class LabValidationResult:
    title: str
    summary: str
    checks: list[LabCheck] = field(default_factory=list)
    suggested_commands: list[str] = field(default_factory=list)


def lab_checklist() -> LabValidationResult:
    checks = [
        LabCheck("Use an isolated lab", "info", "Run real execution only against GNS3, EVE-NG, CHR, IOSv, or similar lab devices."),
        LabCheck("Scan network", "info", "Discover lab devices with the normal safe local scanner.", "python main.py scan"),
        LabCheck("Enrich devices", "info", "Collect passive facts before adding credentials.", "python main.py enrich"),
        LabCheck("Add credentials", "info", "Store SSH credentials with the correct platform hint.", "python main.py credentials add <ip>"),
        LabCheck("Test credentials", "info", "Run an explicit connection test.", "python main.py credentials test <ip>"),
        LabCheck("Collect read-only evidence", "info", "Run safe allowlisted collection before preflight.", "python main.py connect collect <ip>"),
        LabCheck("Create plan", "info", "Create a Cisco VLAN or MikroTik address plan."),
        LabCheck("Review and approve", "info", "Use the approval gate before preflight.", "python main.py plan review <id> && python main.py plan approve <id>"),
        LabCheck("Run preflight", "info", "Preflight must pass before real execution.", "python main.py plan preflight <id> --refresh"),
        LabCheck("Dry-run execution", "info", "Dry-run prints commands and executes nothing.", "python main.py plan execute <id> --dry-run"),
        LabCheck("Execute only in lab", "warning", "Real execution requires exact confirmation and must not be run against production."),
        LabCheck("Verify and rollback", "info", "Verify results and test rollback in the lab.", "python main.py plan verify <id>; python main.py plan rollback <id>"),
    ]
    return LabValidationResult(
        title="Lab Validation Checklist",
        summary="Preparation steps for safe Cisco IOSv/IOSvL2 and MikroTik CHR validation.",
        checks=checks,
    )


def validate_lab_device(ip_address: str) -> LabValidationResult:
    init_db()
    with get_session() as session:
        device = session.scalar(
            select(Device)
            .options(
                selectinload(Device.credentials),
                selectinload(Device.command_runs),
            )
            .where(Device.ip_address == ip_address)
        )

    checks: list[LabCheck] = []
    suggestions = [f"python main.py scan", f"python main.py connect collect {ip_address}"]
    if device is None:
        return LabValidationResult(
            title=f"Lab Device Validation: {ip_address}",
            summary="Device is not present in local inventory.",
            checks=[
                LabCheck(
                    "Inventory",
                    "fail",
                    f"{ip_address} is not in SQLite inventory.",
                    "python main.py scan",
                )
            ],
            suggested_commands=["python main.py scan"],
        )

    checks.append(LabCheck("Inventory", "pass", f"{ip_address} exists in local inventory."))
    credentials = list(device.credentials)
    if not credentials:
        checks.append(
            LabCheck(
                "Credentials",
                "fail",
                "No credentials are stored for this device.",
                f"python main.py credentials add {ip_address}",
            )
        )
        platform = None
    else:
        supported = [cred for cred in credentials if cred.platform_hint in SUPPORTED_LAB_PLATFORMS]
        if supported:
            platform = supported[0].platform_hint
            checks.append(LabCheck("Credentials", "pass", f"Stored credentials include supported platform `{platform}`."))
            status = supported[0].status
            if status in {"success", "ok", "tested", "valid"} or supported[0].last_success_at is not None:
                checks.append(LabCheck("Latest connection status", "pass", f"Credential status is `{status}`."))
            else:
                checks.append(
                    LabCheck(
                        "Latest connection status",
                        "warning",
                        f"Credential status is `{status}` and no last_success_at is stored.",
                        f"python main.py credentials test {ip_address}",
                    )
                )
        else:
            platform = credentials[0].platform_hint
            checks.append(
                LabCheck(
                    "Platform hint",
                    "fail",
                    f"Stored platform `{platform}` is not supported for Phase 16 lab validation.",
                    f"python main.py credentials add {ip_address}",
                )
            )

    if platform in REQUIRED_EVIDENCE:
        history = _latest_successful_commands(device.command_runs)
        for command in REQUIRED_EVIDENCE[platform]:
            if command in history:
                checks.append(LabCheck(f"Evidence: {command}", "pass", "Successful stored command output exists."))
            else:
                checks.append(
                    LabCheck(
                        f"Evidence: {command}",
                        "warning",
                        "No successful stored read-only command output found.",
                        f"python main.py connect collect {ip_address}",
                    )
                )

    return LabValidationResult(
        title=f"Lab Device Validation: {ip_address}",
        summary=_summary_from_checks(checks),
        checks=checks,
        suggested_commands=suggestions,
    )


def validate_lab_plan(plan_id: int) -> LabValidationResult:
    init_db()
    with get_session() as session:
        plan = session.scalar(
            select(ChangePlan)
            .options(
                selectinload(ChangePlan.device).selectinload(Device.credentials),
                selectinload(ChangePlan.device).selectinload(Device.command_runs),
            )
            .where(ChangePlan.id == plan_id)
        )

    if plan is None:
        return LabValidationResult(
            title=f"Lab Plan Validation: {plan_id}",
            summary="Plan was not found.",
            checks=[LabCheck("Plan exists", "fail", f"Change plan {plan_id} was not found.")],
            suggested_commands=["python main.py plan list"],
        )

    checks: list[LabCheck] = [LabCheck("Plan exists", "pass", f"Change plan {plan_id} exists.")]
    if plan.plan_type in SUPPORTED_PLAN_TYPES:
        checks.append(LabCheck("Plan type", "pass", f"`{plan.plan_type}` is supported for lab validation."))
    else:
        checks.append(LabCheck("Plan type", "fail", f"`{plan.plan_type}` is not supported for Phase 16 lab validation."))

    checks.append(
        LabCheck(
            "Approval status",
            "pass" if plan.status == "approved" else "fail",
            f"Plan status is `{plan.status}`.",
            f"python main.py plan approve {plan_id}" if plan.status != "approved" else None,
        )
    )
    checks.append(
        LabCheck(
            "Preflight status",
            "pass" if plan.preflight_status == "passed" else "fail",
            f"Plan preflight_status is `{plan.preflight_status}`.",
            f"python main.py plan preflight {plan_id} --refresh" if plan.preflight_status != "passed" else None,
        )
    )

    if plan.device is None:
        checks.append(LabCheck("Device", "fail", "Plan target device is missing from inventory."))
    else:
        checks.append(LabCheck("Device", "pass", f"Plan targets {plan.device.ip_address}."))
        if plan.device.credentials:
            platforms = ", ".join(sorted({credential.platform_hint for credential in plan.device.credentials}))
            checks.append(LabCheck("Credentials", "pass", f"Stored credential platform(s): {platforms}."))
        else:
            checks.append(
                LabCheck(
                    "Credentials",
                    "fail",
                    "No credentials are stored for the plan target.",
                    f"python main.py credentials add {plan.device.ip_address}",
                )
            )

    try:
        execute_change_plan(plan_id, dry_run=True)
        checks.append(LabCheck("Dry-run", "pass", "Dry-run validation succeeded. No commands were executed."))
    except ConfigExecutionError as exc:
        checks.append(LabCheck("Dry-run", "fail", str(exc), f"python main.py plan show {plan_id}"))

    execution_command = f"python main.py plan execute {plan_id}"
    return LabValidationResult(
        title=f"Lab Plan Validation: {plan_id}",
        summary=_summary_from_checks(checks),
        checks=checks,
        suggested_commands=[
            f"python main.py plan show {plan_id}",
            f"python main.py plan execute {plan_id} --dry-run",
            execution_command,
            f"Type exact confirmation only in the lab: EXECUTE PLAN {plan_id}",
        ],
    )


def _latest_successful_commands(command_runs: list[CommandRun]) -> set[str]:
    return {run.command for run in command_runs if run.success}


def _summary_from_checks(checks: list[LabCheck]) -> str:
    failed = sum(1 for check in checks if check.status == "fail")
    warnings = sum(1 for check in checks if check.status == "warning")
    passed = sum(1 for check in checks if check.status == "pass")
    if failed:
        return f"Not ready for lab execution. pass={passed}, warning={warnings}, fail={failed}."
    if warnings:
        return f"Partially ready. pass={passed}, warning={warnings}, fail=0."
    return f"Ready based on stored local evidence. pass={passed}, warning=0, fail=0."
