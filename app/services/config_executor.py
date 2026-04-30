from __future__ import annotations

import re
import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.database import get_session, init_db
from app.models import ChangePlan, Device, DeviceCredential, ExecutionLog
from app.services.config_snapshot import (
    ConfigSnapshotError,
    capture_post_change_snapshot,
    capture_post_rollback_snapshot,
    capture_pre_change_snapshot,
    capture_pre_rollback_snapshot,
)
from app.services.custom_plan_executor import (
    DOUBLE_CONFIRMATION_PHRASE,
    custom_plan_has_blocked_commands,
    custom_plan_platform,
    custom_plan_precheck_commands,
    custom_plan_requires_double_confirmation,
    custom_plan_verification_commands,
)
from app.services.security import CredentialSecurityError, decrypt_secret


class ConfigExecutionError(RuntimeError):
    """Raised when a change plan cannot be executed safely."""


@dataclass
class ExecutionResult:
    plan: ChangePlan
    log: ExecutionLog | None
    dry_run: bool
    message: str
    proposed_commands: list[str]
    rollback_commands: list[str]


@dataclass(frozen=True)
class MikroTikDhcpParts:
    pool_name: str
    pool_range: str
    dhcp_name: str
    interface: str
    network: str
    gateway: str
    dns: str | None
    comment: str | None


DESTRUCTIVE_EXECUTION_PATTERNS = (
    "reload",
    "erase",
    "delete",
    "format",
    "reset",
    "username",
    "password",
    "enable secret",
    "crypto key",
    "boot system",
)
CISCO_INTERFACE_BLOCKED_PATTERNS = (
    "interface range",
    "switchport mode trunk",
    "switchport trunk",
    "shutdown",
    "no shutdown",
    "channel-group",
    "ip address",
    "router",
    "access-list",
    "line",
    "username",
    "password",
    "enable secret",
    "reload",
    "erase",
    "delete",
    "copy",
    "write",
    "format",
    "crypto",
    "boot",
)
PRE_CHECK_COMMANDS = ("show vlan brief", "show interfaces status", "show interfaces trunk")
POST_CHECK_COMMANDS = ("show vlan brief", "show interfaces status")
VERIFY_COMMANDS = ("show vlan brief", "show interfaces status", "show interfaces trunk")
CISCO_INTERFACE_PRE_CHECK_COMMANDS = ("show interfaces status", "show interfaces trunk", "show vlan brief")
SAFE_CISCO_INTERFACE = r"(?:Gi|GigabitEthernet|Fa|FastEthernet|Te|TenGigabitEthernet|Eth|Ethernet)\d+(?:/\d+){1,3}"
SAFE_CISCO_DESCRIPTION = r"[^;\|&`\$\n\r\x00-\x1f]{1,80}"
SUPPORTED_EXECUTION_PLAN_TYPES = {"vlan", "mikrotik_address", "mikrotik_dhcp_server", "cisco_interface_description", "cisco_access_port", "custom_routeros_plan", "custom_cisco_plan"}
MIKROTIK_PRE_CHECK_COMMANDS = ("/interface print", "/ip address print")
MIKROTIK_POST_CHECK_COMMANDS = ("/ip address print",)
MIKROTIK_VERIFY_COMMANDS = ("/ip address print", "/interface print")
MIKROTIK_DHCP_PRE_CHECK_COMMANDS = (
    "/interface print",
    "/ip address print",
    "/ip pool print",
    "/ip dhcp-server print",
    "/ip dhcp-server network print",
)
MIKROTIK_DHCP_POST_CHECK_COMMANDS = (
    "/ip pool print",
    "/ip dhcp-server print",
    "/ip dhcp-server network print",
)


def execute_change_plan(
    plan_id: int,
    dry_run: bool = False,
    confirmation: str | None = None,
    double_confirmation: str | None = None,
) -> ExecutionResult:
    init_db()
    with get_session() as session:
        plan = _load_plan(session, plan_id)
        proposed = _plan_commands(plan.proposed_commands)
        rollback = _plan_commands(plan.rollback_commands)
        credential = _validate_execution_requirements(plan, proposed, rollback)
        if not dry_run:
            if plan.plan_type in {"custom_routeros_plan", "custom_cisco_plan"}:
                validate_custom_execution_confirmation(plan, confirmation, double_confirmation)
            else:
                validate_execution_confirmation("EXECUTE", plan_id, confirmation)

        if dry_run:
            return ExecutionResult(
                plan=plan,
                log=None,
                dry_run=True,
                message="Dry run only. No commands were executed.",
                proposed_commands=proposed,
                rollback_commands=rollback,
            )

        log = ExecutionLog(
            plan=plan,
            device=plan.device,
            status="started",
            started_at=datetime.now(timezone.utc),
        )
        session.add(log)
        session.commit()
        log_id = log.id

    if plan.plan_type in {"custom_routeros_plan", "custom_cisco_plan"}:
        return _execute_custom_live(plan_id, log_id, credential.id, proposed, rollback, plan.plan_type)
    if credential.platform_hint == "mikrotik_routeros":
        return _execute_mikrotik_live(plan_id, log_id, credential.id, proposed, rollback, plan.plan_type)
    return _execute_live(plan_id, log_id, credential.id, proposed, rollback, plan.plan_type)


def get_execution_history(plan_id: int) -> list[ExecutionLog]:
    init_db()
    with get_session() as session:
        return list(
            session.scalars(
                select(ExecutionLog)
                .options(selectinload(ExecutionLog.plan), selectinload(ExecutionLog.device))
                .where(ExecutionLog.plan_id == plan_id)
                .order_by(ExecutionLog.started_at.desc())
            ).all()
        )


def validate_execution_confirmation(action: str, plan_id: int, confirmation: str | None) -> None:
    expected = f"{action.upper()} PLAN {plan_id}"
    if confirmation != expected:
        raise ConfigExecutionError(f"Confirmation must exactly match `{expected}`.")


def validate_custom_execution_confirmation(plan: ChangePlan, confirmation: str | None, double_confirmation: str | None = None) -> None:
    expected = f"EXECUTE CUSTOM PLAN {plan.id}"
    if confirmation != expected:
        raise ConfigExecutionError(f"Confirmation must exactly match `{expected}`.")
    if custom_plan_requires_double_confirmation(plan) and double_confirmation != DOUBLE_CONFIRMATION_PHRASE:
        raise ConfigExecutionError(f"Double confirmation must exactly match `{DOUBLE_CONFIRMATION_PHRASE}`.")


def validate_cisco_vlan_execution_commands(proposed: list[str], rollback: list[str]) -> None:
    _validate_cisco_vlan_commands(proposed, rollback)


def validate_mikrotik_address_execution_commands(proposed: list[str], rollback: list[str]) -> None:
    _validate_mikrotik_address_commands(proposed, rollback)


def validate_mikrotik_dhcp_execution_commands(proposed: list[str], rollback: list[str]) -> None:
    _validate_mikrotik_dhcp_commands(proposed, rollback)


def validate_cisco_interface_execution_commands(plan_type: str, proposed: list[str], rollback: list[str]) -> None:
    _validate_cisco_interface_commands(plan_type, proposed, rollback)


def verify_change_plan(plan_id: int) -> ExecutionResult:
    init_db()
    with get_session() as session:
        plan = _load_plan(session, plan_id)
        proposed = _plan_commands(plan.proposed_commands)
        rollback = _plan_commands(plan.rollback_commands)
        credential = _validate_post_execution_plan(plan, proposed, rollback)
        log = ExecutionLog(
            plan=plan,
            device=plan.device,
            status="started",
            started_at=datetime.now(timezone.utc),
        )
        session.add(log)
        session.commit()
        log_id = log.id

    connection = None
    try:
        with get_session() as session:
            credential = session.scalar(
                select(DeviceCredential)
                .options(selectinload(DeviceCredential.device))
                .where(DeviceCredential.id == credential.id)
            )
            if credential is None:
                raise ConfigExecutionError("Stored credentials were removed before verification.")
            connection = _open_connection_for_credential(credential)
        if plan.plan_type == "mikrotik_address":
            output = _run_show_commands(connection, MIKROTIK_VERIFY_COMMANDS)
            status, message = _mikrotik_verification_status(proposed, output)
        elif plan.plan_type == "mikrotik_dhcp_server":
            output = _run_show_commands(connection, MIKROTIK_DHCP_POST_CHECK_COMMANDS)
            status, message = _mikrotik_dhcp_verification_status(proposed, output)
        elif plan.plan_type in {"cisco_interface_description", "cisco_access_port"}:
            commands = _cisco_interface_verify_commands(proposed)
            output = _run_show_commands(connection, commands)
            status, message = _cisco_interface_verification_status(plan.plan_type, proposed, output)
        elif plan.plan_type in {"custom_routeros_plan", "custom_cisco_plan"}:
            output = _run_show_commands(connection, custom_plan_verification_commands(plan))
            ok = _custom_verification_passed(output)
            status, message = ("verified", "Custom plan verification passed.") if ok else ("verification_failed", "Custom plan verification failed.")
        else:
            output = _run_show_commands(connection, VERIFY_COMMANDS)
            status, message = _verification_status(proposed, output)
        return _finish_execution(
            plan_id=plan_id,
            log_id=log_id,
            status=status,
            plan_status=plan.status,
            pre_check_output=output,
            execution_output="",
            post_check_output=output,
            rollback_output="",
            error_message=None if status == "verified" else message,
            dry_run=False,
            message=message,
            proposed=proposed,
            rollback=rollback,
        )
    except Exception as exc:
        return _finish_execution(
            plan_id=plan_id,
            log_id=log_id,
            status="verification_failed",
            plan_status=plan.status,
            pre_check_output="",
            execution_output="",
            post_check_output="",
            rollback_output="",
            error_message=str(exc),
            dry_run=False,
            message="Verification failed.",
            proposed=proposed,
            rollback=rollback,
        )
    finally:
        if connection is not None:
            connection.disconnect()


def save_plan_config(plan_id: int, confirmation: str | None = None) -> ExecutionResult:
    expected = f"SAVE CONFIG PLAN {plan_id}"
    if confirmation != expected:
        raise ConfigExecutionError(f"Confirmation must exactly match `{expected}`.")
    init_db()
    with get_session() as session:
        plan = _load_plan(session, plan_id)
        if plan.plan_type in {"mikrotik_address", "mikrotik_dhcp_server"}:
            raise ConfigExecutionError(
                "MikroTik RouterOS applies DHCP changes immediately. There is no separate save step for this plan type."
                if plan.plan_type == "mikrotik_dhcp_server"
                else "MikroTik RouterOS applies changes immediately. There is no separate save step for this plan type."
            )
        proposed = _plan_commands(plan.proposed_commands)
        rollback = _plan_commands(plan.rollback_commands)
        credential = _validate_save_requirements(plan, proposed, rollback)
        log = ExecutionLog(
            plan=plan,
            device=plan.device,
            status="started",
            started_at=datetime.now(timezone.utc),
        )
        session.add(log)
        session.commit()
        log_id = log.id

    connection = None
    try:
        with get_session() as session:
            credential = session.scalar(
                select(DeviceCredential)
                .options(selectinload(DeviceCredential.device))
                .where(DeviceCredential.id == credential.id)
            )
            if credential is None:
                raise ConfigExecutionError("Stored credentials were removed before save.")
            connection = _open_cisco_connection(credential)
        output = connection.send_command_timing("write memory", read_timeout=60)
        return _finish_execution(
            plan_id=plan_id,
            log_id=log_id,
            status="save_success",
            plan_status="saved",
            pre_check_output="",
            execution_output=output,
            post_check_output="",
            rollback_output="",
            error_message=None,
            dry_run=False,
            message="Configuration saved with `write memory`.",
            proposed=proposed,
            rollback=rollback,
        )
    except Exception as exc:
        return _finish_execution(
            plan_id=plan_id,
            log_id=log_id,
            status="save_failed",
            plan_status=plan.status,
            pre_check_output="",
            execution_output="",
            post_check_output="",
            rollback_output="",
            error_message=str(exc),
            dry_run=False,
            message="Configuration save failed.",
            proposed=proposed,
            rollback=rollback,
        )
    finally:
        if connection is not None:
            connection.disconnect()


def rollback_change_plan(plan_id: int, confirmation: str | None = None) -> ExecutionResult:
    validate_execution_confirmation("ROLLBACK", plan_id, confirmation)
    init_db()
    with get_session() as session:
        plan = _load_plan(session, plan_id)
        proposed = _plan_commands(plan.proposed_commands)
        rollback = _plan_commands(plan.rollback_commands)
        credential = _validate_rollback_requirements(plan, proposed, rollback)
        log = ExecutionLog(
            plan=plan,
            device=plan.device,
            status="started",
            started_at=datetime.now(timezone.utc),
        )
        session.add(log)
        session.commit()
        log_id = log.id

    connection = None
    try:
        with get_session() as session:
            credential = session.scalar(
                select(DeviceCredential)
                .options(selectinload(DeviceCredential.device))
                .where(DeviceCredential.id == credential.id)
            )
            if credential is None:
                raise ConfigExecutionError("Stored credentials were removed before rollback.")
            connection = _open_connection_for_credential(credential)
        capture_pre_rollback_snapshot(plan_id, connection=connection, execution_log_id=log_id)
        if plan.plan_type == "mikrotik_address":
            rollback_output = _send_mikrotik_command(connection, rollback[0])
            verify_output = _run_show_commands(connection, MIKROTIK_POST_CHECK_COMMANDS)
            status, verify_message = _mikrotik_rollback_verification_status(proposed, verify_output)
        elif plan.plan_type == "mikrotik_dhcp_server":
            rollback_output = _send_mikrotik_commands(connection, rollback)
            verify_output = _run_show_commands(connection, MIKROTIK_DHCP_POST_CHECK_COMMANDS)
            status, verify_message = _mikrotik_dhcp_rollback_verification_status(proposed, verify_output)
        elif plan.plan_type in {"cisco_interface_description", "cisco_access_port"}:
            rollback_output = connection.send_config_set(rollback)
            verify_output = _run_show_commands(connection, _cisco_interface_verify_commands(proposed))
            status, verify_message = _cisco_interface_rollback_verification_status(plan.plan_type, proposed, verify_output)
        elif plan.plan_type in {"custom_routeros_plan", "custom_cisco_plan"}:
            if plan.plan_type == "custom_routeros_plan":
                rollback_output = _send_mikrotik_commands(connection, rollback)
            else:
                rollback_output = connection.send_config_set(rollback)
            verify_output = _run_show_commands(connection, custom_plan_verification_commands(plan))
            status, verify_message = (
                ("manual_rollback_success", "Custom rollback verification passed.")
                if _custom_verification_passed(verify_output)
                else ("manual_rollback_failed", "Custom rollback verification failed.")
            )
        else:
            rollback_output = connection.send_config_set(rollback)
            verify_output = _run_show_commands(connection, VERIFY_COMMANDS)
            status, verify_message = _rollback_verification_status(proposed, verify_output)
        snapshot_warning = _try_capture_post_rollback_snapshot(plan_id, connection, log_id)
        if snapshot_warning:
            rollback_output += snapshot_warning
        return _finish_execution(
            plan_id=plan_id,
            log_id=log_id,
            status=status,
            plan_status="rolled_back" if status == "manual_rollback_success" else plan.status,
            pre_check_output="",
            execution_output="",
            post_check_output=verify_output,
            rollback_output=rollback_output,
            error_message=None if status == "manual_rollback_success" else verify_message,
            dry_run=False,
            message=verify_message,
            proposed=proposed,
            rollback=rollback,
        )
    except Exception as exc:
        return _finish_execution(
            plan_id=plan_id,
            log_id=log_id,
            status="manual_rollback_failed",
            plan_status=plan.status,
            pre_check_output="",
            execution_output="",
            post_check_output="",
            rollback_output="",
            error_message=str(exc),
            dry_run=False,
            message="Manual rollback failed.",
            proposed=proposed,
            rollback=rollback,
        )
    finally:
        if connection is not None:
            connection.disconnect()


def _execute_live(
    plan_id: int,
    log_id: int,
    credential_id: int,
    proposed: list[str],
    rollback: list[str],
    plan_type: str,
) -> ExecutionResult:
    connection = None
    execution_attempted = False
    pre_output = ""
    execution_output = ""
    post_output = ""
    try:
        with get_session() as session:
            credential = session.scalar(
                select(DeviceCredential)
                .options(selectinload(DeviceCredential.device))
                .where(DeviceCredential.id == credential_id)
            )
            if credential is None:
                raise ConfigExecutionError("Stored credentials were removed before execution.")
            connection = _open_cisco_connection(credential)

        capture_pre_change_snapshot(plan_id, connection=connection, execution_log_id=log_id)
        pre_commands = _cisco_interface_pre_check_commands() if plan_type in {"cisco_interface_description", "cisco_access_port"} else PRE_CHECK_COMMANDS
        post_commands = _cisco_interface_verify_commands(proposed) if plan_type in {"cisco_interface_description", "cisco_access_port"} else POST_CHECK_COMMANDS
        pre_output = _run_show_commands(connection, pre_commands)
        execution_attempted = True
        execution_output = connection.send_config_set(proposed)
        post_output = _run_show_commands(connection, post_commands)

        verified = (
            _verify_cisco_interface_result(plan_type, proposed, post_output)
            if plan_type in {"cisco_interface_description", "cisco_access_port"}
            else _verify_vlan_result(proposed, post_output)
        )
        if verified:
            snapshot_warning = _try_capture_post_change_snapshot(plan_id, connection, log_id)
            if snapshot_warning:
                post_output += snapshot_warning
            return _finish_execution(
                plan_id=plan_id,
                log_id=log_id,
                status="success",
                plan_status="executed",
                pre_check_output=pre_output,
                execution_output=execution_output,
                post_check_output=post_output,
                rollback_output="",
                error_message=None,
                dry_run=False,
                message="Execution succeeded. No startup-config save was performed.",
                proposed=proposed,
                rollback=rollback,
            )

        rollback_warning = _try_capture_pre_rollback_snapshot(plan_id, connection, log_id)
        rollback_output = connection.send_config_set(rollback)
        rollback_output += "\n\nPOST-ROLLBACK CHECKS\n" + _run_show_commands(connection, post_commands)
        rollback_output += _try_capture_post_rollback_snapshot(plan_id, connection, log_id)
        if rollback_warning:
            rollback_output += rollback_warning
        return _finish_execution(
            plan_id=plan_id,
            log_id=log_id,
            status="rolled_back",
            plan_status="rolled_back",
            pre_check_output=pre_output,
            execution_output=execution_output,
            post_check_output=post_output,
            rollback_output=rollback_output,
            error_message="Post-check verification failed; rollback commands were applied automatically.",
            dry_run=False,
            message="Execution verification failed and rollback was applied.",
            proposed=proposed,
            rollback=rollback,
        )
    except Exception as exc:
        rollback_output = ""
        status = "failed"
        plan_status = "approved" if not execution_attempted else "execution_failed"
        if connection is not None and execution_attempted:
            try:
                rollback_warning = _try_capture_pre_rollback_snapshot(plan_id, connection, log_id)
                rollback_output = connection.send_config_set(rollback)
                rollback_output += _try_capture_post_rollback_snapshot(plan_id, connection, log_id)
                if rollback_warning:
                    rollback_output += rollback_warning
                status = "rolled_back"
                plan_status = "rolled_back"
            except Exception as rollback_exc:
                rollback_output = str(rollback_exc)
                status = "rollback_failed"
                plan_status = "execution_failed"
        message = "Execution failed with status `{status}`."
        if isinstance(exc, ConfigSnapshotError) and not execution_attempted:
            message = "Pre-change snapshot failed. Execution was not started."
        return _finish_execution(
            plan_id=plan_id,
            log_id=log_id,
            status=status,
            plan_status=plan_status,
            pre_check_output=pre_output,
            execution_output=execution_output,
            post_check_output=post_output,
            rollback_output=rollback_output,
            error_message=str(exc),
            dry_run=False,
            message=message.format(status=status),
            proposed=proposed,
            rollback=rollback,
        )
    finally:
        if connection is not None:
            connection.disconnect()


def _execute_mikrotik_live(
    plan_id: int,
    log_id: int,
    credential_id: int,
    proposed: list[str],
    rollback: list[str],
    plan_type: str,
) -> ExecutionResult:
    connection = None
    execution_attempted = False
    pre_output = ""
    execution_output = ""
    post_output = ""
    try:
        with get_session() as session:
            credential = session.scalar(
                select(DeviceCredential)
                .options(selectinload(DeviceCredential.device))
                .where(DeviceCredential.id == credential_id)
            )
            if credential is None:
                raise ConfigExecutionError("Stored credentials were removed before execution.")
            connection = _open_mikrotik_connection(credential)

        capture_pre_change_snapshot(plan_id, connection=connection, execution_log_id=log_id)
        pre_commands = MIKROTIK_DHCP_PRE_CHECK_COMMANDS if plan_type == "mikrotik_dhcp_server" else MIKROTIK_PRE_CHECK_COMMANDS
        post_commands = MIKROTIK_DHCP_POST_CHECK_COMMANDS if plan_type == "mikrotik_dhcp_server" else MIKROTIK_POST_CHECK_COMMANDS
        pre_output = _run_show_commands(connection, pre_commands)
        execution_attempted = True
        execution_output = _send_mikrotik_commands(connection, proposed)
        post_output = _run_show_commands(connection, post_commands)

        verified = (
            _verify_mikrotik_dhcp_result(proposed, post_output)
            if plan_type == "mikrotik_dhcp_server"
            else _verify_mikrotik_address_result(proposed, post_output)
        )
        if verified:
            snapshot_warning = _try_capture_post_change_snapshot(plan_id, connection, log_id)
            if snapshot_warning:
                post_output += snapshot_warning
            return _finish_execution(
                plan_id=plan_id,
                log_id=log_id,
                status="success",
                plan_status="executed",
                pre_check_output=pre_output,
                execution_output=execution_output,
                post_check_output=post_output,
                rollback_output="",
                error_message=None,
                dry_run=False,
                message=(
                    "MikroTik DHCP execution succeeded. RouterOS applies DHCP changes immediately."
                    if plan_type == "mikrotik_dhcp_server"
                    else "MikroTik execution succeeded. RouterOS applies this change immediately."
                ),
                proposed=proposed,
                rollback=rollback,
            )

        rollback_warning = _try_capture_pre_rollback_snapshot(plan_id, connection, log_id)
        rollback_output = _send_mikrotik_commands(connection, rollback)
        rollback_output += "\n\nPOST-ROLLBACK CHECKS\n" + _run_show_commands(connection, post_commands)
        rollback_output += _try_capture_post_rollback_snapshot(plan_id, connection, log_id)
        if rollback_warning:
            rollback_output += rollback_warning
        return _finish_execution(
            plan_id=plan_id,
            log_id=log_id,
            status="rolled_back",
            plan_status="rolled_back",
            pre_check_output=pre_output,
            execution_output=execution_output,
            post_check_output=post_output,
            rollback_output=rollback_output,
            error_message="Post-check verification failed; rollback command was applied automatically.",
            dry_run=False,
            message="MikroTik execution verification failed and rollback was applied.",
            proposed=proposed,
            rollback=rollback,
        )
    except Exception as exc:
        rollback_output = ""
        status = "failed"
        plan_status = "approved" if not execution_attempted else "execution_failed"
        if connection is not None and execution_attempted:
            try:
                rollback_warning = _try_capture_pre_rollback_snapshot(plan_id, connection, log_id)
                rollback_output = _send_mikrotik_commands(connection, rollback)
                rollback_output += _try_capture_post_rollback_snapshot(plan_id, connection, log_id)
                if rollback_warning:
                    rollback_output += rollback_warning
                status = "rolled_back"
                plan_status = "rolled_back"
            except Exception as rollback_exc:
                rollback_output = str(rollback_exc)
                status = "rollback_failed"
                plan_status = "execution_failed"
        message = "MikroTik execution failed with status `{status}`."
        if isinstance(exc, ConfigSnapshotError) and not execution_attempted:
            message = "Pre-change snapshot failed. Execution was not started."
        return _finish_execution(
            plan_id=plan_id,
            log_id=log_id,
            status=status,
            plan_status=plan_status,
            pre_check_output=pre_output,
            execution_output=execution_output,
            post_check_output=post_output,
            rollback_output=rollback_output,
            error_message=str(exc),
            dry_run=False,
            message=message.format(status=status),
            proposed=proposed,
            rollback=rollback,
        )
    finally:
        if connection is not None:
            connection.disconnect()


def _execute_custom_live(
    plan_id: int,
    log_id: int,
    credential_id: int,
    proposed: list[str],
    rollback: list[str],
    plan_type: str,
) -> ExecutionResult:
    connection = None
    execution_attempted = False
    pre_output = ""
    execution_output = ""
    post_output = ""
    platform = "mikrotik_routeros" if plan_type == "custom_routeros_plan" else "cisco_ios"
    try:
        with get_session() as session:
            credential = session.scalar(
                select(DeviceCredential)
                .options(selectinload(DeviceCredential.device))
                .where(DeviceCredential.id == credential_id)
            )
            if credential is None:
                raise ConfigExecutionError("Stored credentials were removed before execution.")
            connection = _open_mikrotik_connection(credential) if platform == "mikrotik_routeros" else _open_cisco_connection(credential)
            plan = _load_plan(session, plan_id)
            pre_commands = custom_plan_precheck_commands(plan)
            verification_commands = custom_plan_verification_commands(plan)

        capture_pre_change_snapshot(plan_id, connection=connection, execution_log_id=log_id)
        pre_output = _run_show_commands(connection, pre_commands) if pre_commands else ""
        execution_attempted = True
        execution_output = (
            _send_mikrotik_commands(connection, proposed)
            if platform == "mikrotik_routeros"
            else connection.send_config_set(proposed)
        )
        post_output = _run_show_commands(connection, verification_commands)
        if _custom_verification_passed(post_output):
            snapshot_warning = _try_capture_post_change_snapshot(plan_id, connection, log_id)
            if snapshot_warning:
                post_output += snapshot_warning
            return _finish_execution(
                plan_id=plan_id,
                log_id=log_id,
                status="success",
                plan_status="executed",
                pre_check_output=pre_output,
                execution_output=execution_output,
                post_check_output=post_output,
                rollback_output="",
                error_message=None,
                dry_run=False,
                message="Custom plan execution succeeded. Cisco startup-config was not saved automatically.",
                proposed=proposed,
                rollback=rollback,
            )

        rollback_warning = _try_capture_pre_rollback_snapshot(plan_id, connection, log_id)
        rollback_output = (
            _send_mikrotik_commands(connection, rollback)
            if platform == "mikrotik_routeros"
            else connection.send_config_set(rollback)
        )
        rollback_output += "\n\nPOST-ROLLBACK CHECKS\n" + _run_show_commands(connection, verification_commands)
        rollback_output += _try_capture_post_rollback_snapshot(plan_id, connection, log_id)
        if rollback_warning:
            rollback_output += rollback_warning
        return _finish_execution(
            plan_id=plan_id,
            log_id=log_id,
            status="rolled_back",
            plan_status="rolled_back",
            pre_check_output=pre_output,
            execution_output=execution_output,
            post_check_output=post_output,
            rollback_output=rollback_output,
            error_message="Custom verification failed; rollback commands were applied automatically.",
            dry_run=False,
            message="Custom plan verification failed and rollback was applied.",
            proposed=proposed,
            rollback=rollback,
        )
    except Exception as exc:
        rollback_output = ""
        status = "failed"
        plan_status = "approved" if not execution_attempted else "execution_failed"
        if connection is not None and execution_attempted:
            try:
                rollback_warning = _try_capture_pre_rollback_snapshot(plan_id, connection, log_id)
                rollback_output = (
                    _send_mikrotik_commands(connection, rollback)
                    if platform == "mikrotik_routeros"
                    else connection.send_config_set(rollback)
                )
                rollback_output += _try_capture_post_rollback_snapshot(plan_id, connection, log_id)
                if rollback_warning:
                    rollback_output += rollback_warning
                status = "rolled_back"
                plan_status = "rolled_back"
            except Exception as rollback_exc:
                rollback_output = str(rollback_exc)
                status = "rollback_failed"
                plan_status = "execution_failed"
        message = "Custom plan execution failed with status `{status}`."
        if isinstance(exc, ConfigSnapshotError) and not execution_attempted:
            message = "Pre-change snapshot failed. Execution was not started."
        return _finish_execution(
            plan_id=plan_id,
            log_id=log_id,
            status=status,
            plan_status=plan_status,
            pre_check_output=pre_output,
            execution_output=execution_output,
            post_check_output=post_output,
            rollback_output=rollback_output,
            error_message=str(exc),
            dry_run=False,
            message=message.format(status=status),
            proposed=proposed,
            rollback=rollback,
        )
    finally:
        if connection is not None:
            connection.disconnect()


def _try_capture_post_change_snapshot(plan_id: int, connection, log_id: int) -> str:
    try:
        capture_post_change_snapshot(plan_id, connection=connection, execution_log_id=log_id)
    except Exception as exc:
        return f"\n\nPOST-CHANGE SNAPSHOT WARNING\n{exc}"
    return ""


def _try_capture_pre_rollback_snapshot(plan_id: int, connection, log_id: int) -> str:
    try:
        capture_pre_rollback_snapshot(plan_id, connection=connection, execution_log_id=log_id)
    except Exception as exc:
        return f"\n\nPRE-ROLLBACK SNAPSHOT WARNING\n{exc}"
    return ""


def _try_capture_post_rollback_snapshot(plan_id: int, connection, log_id: int) -> str:
    try:
        capture_post_rollback_snapshot(plan_id, connection=connection, execution_log_id=log_id)
    except Exception as exc:
        return f"\n\nPOST-ROLLBACK SNAPSHOT WARNING\n{exc}"
    return ""


def _custom_verification_passed(output: str) -> bool:
    lowered = output.lower()
    failure_markers = ("invalid input", "bad command", "failure", "failed", "error:")
    return not any(marker in lowered for marker in failure_markers)


def _finish_execution(
    plan_id: int,
    log_id: int,
    status: str,
    plan_status: str,
    pre_check_output: str,
    execution_output: str,
    post_check_output: str,
    rollback_output: str,
    error_message: str | None,
    dry_run: bool,
    message: str,
    proposed: list[str],
    rollback: list[str],
) -> ExecutionResult:
    with get_session() as session:
        plan = _load_plan(session, plan_id)
        log = session.get(ExecutionLog, log_id)
        if log is None:
            raise ConfigExecutionError("Execution log disappeared before completion.")
        now = datetime.now(timezone.utc)
        log.status = status
        log.finished_at = now
        log.pre_check_output = pre_check_output
        log.execution_output = execution_output
        log.post_check_output = post_check_output
        log.rollback_output = rollback_output
        log.error_message = error_message
        plan.status = plan_status
        plan.updated_at = now
        session.commit()
        saved_log = session.scalar(
            select(ExecutionLog)
            .options(selectinload(ExecutionLog.device), selectinload(ExecutionLog.plan))
            .where(ExecutionLog.id == log_id)
        )
        return ExecutionResult(
            plan=_load_plan(session, plan_id),
            log=saved_log,
            dry_run=dry_run,
            message=message,
            proposed_commands=proposed,
            rollback_commands=rollback,
        )


def _validate_execution_requirements(
    plan: ChangePlan,
    proposed: list[str],
    rollback: list[str],
) -> DeviceCredential:
    if plan.status != "approved":
        raise ConfigExecutionError(f"Plan status must be `approved`; current status is `{plan.status}`.")
    if plan.preflight_status != "passed":
        raise ConfigExecutionError(
            f"Plan preflight_status must be `passed`; current status is `{plan.preflight_status}`."
        )
    if plan.plan_type not in SUPPORTED_EXECUTION_PLAN_TYPES:
        raise ConfigExecutionError(_unsupported_plan_type_message(plan.plan_type))
    if plan.device is None:
        raise ConfigExecutionError("Plan target device is missing from inventory.")
    if not proposed:
        raise ConfigExecutionError("Proposed commands are empty.")
    if not rollback:
        raise ConfigExecutionError("Rollback commands are empty.")

    if plan.plan_type == "mikrotik_address":
        credential = _mikrotik_credential(plan.device)
        _validate_mikrotik_address_commands(proposed, rollback)
        return credential
    if plan.plan_type == "mikrotik_dhcp_server":
        credential = _mikrotik_credential(plan.device)
        _validate_mikrotik_dhcp_commands(proposed, rollback)
        return credential
    if plan.plan_type in {"custom_routeros_plan", "custom_cisco_plan"}:
        if custom_plan_has_blocked_commands(plan):
            raise ConfigExecutionError("Custom plan contains blocked security-abuse commands.")
        if not custom_plan_verification_commands(plan):
            raise ConfigExecutionError("Custom plan requires verification commands.")
        credential = _mikrotik_credential(plan.device) if plan.plan_type == "custom_routeros_plan" else _cisco_credential(plan.device)
        if credential.platform_hint != custom_plan_platform(plan):
            raise ConfigExecutionError("Custom plan platform does not match saved credentials.")
        return credential
    if plan.plan_type in {"cisco_interface_description", "cisco_access_port"}:
        credential = _cisco_credential(plan.device)
        _validate_cisco_interface_commands(plan.plan_type, proposed, rollback)
        return credential
    credential = _cisco_credential(plan.device)
    _validate_cisco_vlan_commands(proposed, rollback)
    return credential


def _validate_post_execution_plan(
    plan: ChangePlan,
    proposed: list[str],
    rollback: list[str],
) -> DeviceCredential:
    if plan.plan_type not in SUPPORTED_EXECUTION_PLAN_TYPES:
        raise ConfigExecutionError(_unsupported_plan_type_message(plan.plan_type))
    if plan.device is None:
        raise ConfigExecutionError("Plan target device is missing from inventory.")
    if not proposed:
        raise ConfigExecutionError("Proposed commands are empty.")
    if not rollback:
        raise ConfigExecutionError("Rollback commands are empty.")
    if plan.plan_type == "mikrotik_address":
        credential = _mikrotik_credential(plan.device)
        _validate_mikrotik_address_commands(proposed, rollback)
        return credential
    if plan.plan_type == "mikrotik_dhcp_server":
        credential = _mikrotik_credential(plan.device)
        _validate_mikrotik_dhcp_commands(proposed, rollback)
        return credential
    if plan.plan_type in {"custom_routeros_plan", "custom_cisco_plan"}:
        if custom_plan_has_blocked_commands(plan):
            raise ConfigExecutionError("Custom plan contains blocked security-abuse commands.")
        return _mikrotik_credential(plan.device) if plan.plan_type == "custom_routeros_plan" else _cisco_credential(plan.device)
    if plan.plan_type in {"cisco_interface_description", "cisco_access_port"}:
        credential = _cisco_credential(plan.device)
        _validate_cisco_interface_commands(plan.plan_type, proposed, rollback)
        return credential
    credential = _cisco_credential(plan.device)
    _validate_cisco_vlan_commands(proposed, rollback)
    return credential


def _validate_save_requirements(
    plan: ChangePlan,
    proposed: list[str],
    rollback: list[str],
) -> DeviceCredential:
    if plan.plan_type not in SUPPORTED_EXECUTION_PLAN_TYPES:
        raise ConfigExecutionError(_unsupported_plan_type_message(plan.plan_type))
    if plan.status != "executed":
        raise ConfigExecutionError(f"Plan status must be `executed`; current status is `{plan.status}`.")
    credential = _validate_post_execution_plan(plan, proposed, rollback)
    latest = _latest_verification_log(plan)
    if latest is None or latest.status != "verified":
        raise ConfigExecutionError("Latest verification result must be `passed` before saving config.")
    return credential


def _validate_rollback_requirements(
    plan: ChangePlan,
    proposed: list[str],
    rollback: list[str],
) -> DeviceCredential:
    if plan.plan_type not in SUPPORTED_EXECUTION_PLAN_TYPES:
        raise ConfigExecutionError(_unsupported_plan_type_message(plan.plan_type))
    if plan.plan_type in {"mikrotik_address", "mikrotik_dhcp_server"} and plan.status == "rolled_back":
        raise ConfigExecutionError("MikroTik plan has already been rolled back. Force rollback is not supported in this phase.")
    allowed = {"executed", "execution_failed"} if plan.plan_type in {"mikrotik_address", "mikrotik_dhcp_server"} else {"executed", "execution_failed", "saved"}
    if plan.status not in allowed:
        raise ConfigExecutionError(
            "Manual rollback requires an executed or failed execution plan status."
        )
    return _validate_post_execution_plan(plan, proposed, rollback)


def _cisco_credential(device: Device) -> DeviceCredential:
    for credential in device.credentials:
        if credential.connection_type == "ssh" and credential.platform_hint == "cisco_ios":
            return credential
    raise ConfigExecutionError("Device must have saved SSH credentials with platform `cisco_ios`.")


def _mikrotik_credential(device: Device) -> DeviceCredential:
    for credential in device.credentials:
        if credential.connection_type == "ssh" and credential.platform_hint == "mikrotik_routeros":
            return credential
    raise ConfigExecutionError("Device must have saved SSH credentials with platform `mikrotik_routeros`.")


def _unsupported_plan_type_message(plan_type: str) -> str:
    return "Only Cisco VLAN/interface/custom, MikroTik address/DHCP/custom plans are supported for execution operations."


def _validate_cisco_vlan_commands(proposed: list[str], rollback: list[str]) -> None:
    for command in proposed + rollback:
        lowered = command.lower().strip()
        if not lowered:
            raise ConfigExecutionError("Empty commands are not allowed.")
        for pattern in DESTRUCTIVE_EXECUTION_PATTERNS:
            if pattern in lowered:
                raise ConfigExecutionError(f"Unsafe command blocked: `{command}`.")
        if "switchport mode trunk" in lowered or "interface trunk" in lowered:
            raise ConfigExecutionError(f"Trunk changes are not supported in Phase 10: `{command}`.")

    if not proposed[0].lower().startswith("vlan "):
        raise ConfigExecutionError("VLAN plans must start with `vlan <id>`.")
    vlan_id = _vlan_id_from_commands(proposed)
    if vlan_id is None:
        raise ConfigExecutionError("Could not parse VLAN ID from proposed commands.")

    for command in proposed:
        if not _allowed_proposed_command(command, vlan_id):
            raise ConfigExecutionError(f"Command is outside the Phase 10 VLAN template: `{command}`.")
    for command in rollback:
        if not _allowed_rollback_command(command, vlan_id):
            raise ConfigExecutionError(f"Rollback command is outside the Phase 10 VLAN template: `{command}`.")


def _validate_mikrotik_address_commands(proposed: list[str], rollback: list[str]) -> None:
    if len(proposed) != 1:
        raise ConfigExecutionError("MikroTik address execution requires exactly one proposed command.")
    if len(rollback) != 1:
        raise ConfigExecutionError("MikroTik address execution requires exactly one rollback command.")
    proposed_parts = _mikrotik_parts_from_proposed(proposed[0])
    rollback_parts = _mikrotik_parts_from_rollback(rollback[0])
    if proposed_parts is None:
        raise ConfigExecutionError("MikroTik proposed command is outside the strict address-add template.")
    if rollback_parts is None:
        raise ConfigExecutionError("MikroTik rollback command is outside the strict address-remove template.")
    if proposed_parts[:2] != rollback_parts:
        raise ConfigExecutionError("MikroTik rollback command does not match the proposed address/interface.")
    _validate_private_cidr(proposed_parts[0])
    for command in proposed + rollback:
        _reject_mikrotik_unsafe_command(command)


def _validate_mikrotik_dhcp_commands(proposed: list[str], rollback: list[str]) -> None:
    parts = _mikrotik_dhcp_parts_from_commands(proposed, rollback)
    if parts is None:
        raise ConfigExecutionError("MikroTik DHCP commands are outside the strict generated templates.")
    _validate_private_network(parts.network)
    _validate_gateway_in_network(parts.gateway, parts.network)
    _validate_pool_range(parts.pool_range, parts.network)
    for command in proposed + rollback:
        _reject_mikrotik_dhcp_unsafe_command(command)


def _validate_cisco_interface_commands(plan_type: str, proposed: list[str], rollback: list[str]) -> None:
    if plan_type not in {"cisco_interface_description", "cisco_access_port"}:
        raise ConfigExecutionError(f"Unsupported Cisco interface plan type `{plan_type}`.")
    if len(proposed) < 2 or len(rollback) < 2:
        raise ConfigExecutionError("Cisco interface plans require interface and action commands.")
    proposed_clean = [command.strip() for command in proposed]
    rollback_clean = [command.strip() for command in rollback]
    for command in proposed_clean + rollback_clean:
        _reject_cisco_interface_unsafe_command(command)
    interface = _interface_from_line(proposed_clean[0])
    rollback_interface = _interface_from_line(rollback_clean[0])
    if interface is None or rollback_interface != interface:
        raise ConfigExecutionError("Cisco interface proposed and rollback commands must target the same single interface.")

    if plan_type == "cisco_interface_description":
        if len(proposed_clean) != 2 or len(rollback_clean) != 2:
            raise ConfigExecutionError("Cisco description plans must contain exactly two proposed and two rollback commands.")
        if not re.fullmatch(rf"description {SAFE_CISCO_DESCRIPTION}", proposed_clean[1], flags=re.IGNORECASE):
            raise ConfigExecutionError("Cisco description command is outside the allowed template.")
        if rollback_clean[1].lower() != "no description":
            raise ConfigExecutionError("Cisco description rollback must be `no description`.")
        return

    if "switchport mode access" not in [command.lower() for command in proposed_clean]:
        raise ConfigExecutionError("Cisco access-port plan must include `switchport mode access`.")
    vlan_id = _access_vlan_from_commands(proposed_clean)
    if vlan_id is None:
        raise ConfigExecutionError("Cisco access-port plan must include `switchport access vlan <id>`.")
    if vlan_id < 1 or vlan_id > 4094:
        raise ConfigExecutionError("Cisco access VLAN ID must be 1-4094.")
    allowed_proposed = {
        f"interface {interface}",
        "switchport mode access",
        f"switchport access vlan {vlan_id}",
        "spanning-tree portfast",
    }
    allowed_rollback = {
        f"interface {interface}",
        f"no switchport access vlan {vlan_id}",
        "no spanning-tree portfast",
        "no description",
    }
    for command in proposed_clean:
        if command.lower().startswith("description "):
            if not re.fullmatch(rf"description {SAFE_CISCO_DESCRIPTION}", command, flags=re.IGNORECASE):
                raise ConfigExecutionError("Cisco description command is outside the allowed template.")
            continue
        if command not in allowed_proposed:
            raise ConfigExecutionError(f"Cisco access-port command is outside the allowed template: `{command}`.")
    for command in rollback_clean:
        if command not in allowed_rollback:
            raise ConfigExecutionError(f"Cisco access-port rollback command is outside the allowed template: `{command}`.")


def _reject_cisco_interface_unsafe_command(command: str) -> None:
    if not command:
        raise ConfigExecutionError("Empty commands are not allowed.")
    if any(char in command for char in (";", "|", "&", "`", "$", "\n", "\r")):
        raise ConfigExecutionError(f"Cisco interface command contains unsafe characters: `{command}`.")
    lowered = command.lower()
    for pattern in CISCO_INTERFACE_BLOCKED_PATTERNS:
        if pattern in lowered:
            raise ConfigExecutionError(f"Cisco interface command blocked by safety policy: `{pattern}`.")


def _interface_from_line(command: str) -> str | None:
    match = re.fullmatch(rf"interface ({SAFE_CISCO_INTERFACE})", command, flags=re.IGNORECASE)
    return match.group(1) if match else None


def _access_vlan_from_commands(commands: list[str]) -> int | None:
    for command in commands:
        match = re.fullmatch(r"switchport access vlan (\d+)", command, flags=re.IGNORECASE)
        if match:
            return int(match.group(1))
    return None


def _mikrotik_parts_from_proposed(command: str) -> tuple[str, str, str | None] | None:
    match = re.fullmatch(
        r'/ip address add address=([0-9.]+/\d{1,2}) interface=([A-Za-z0-9_.\-/]+)(?: comment="([^"\n\r;`|&$\[\]]{1,64})")?',
        command.strip(),
    )
    if not match:
        return None
    return match.group(1), match.group(2), match.group(3)


def _mikrotik_parts_from_rollback(command: str) -> tuple[str, str] | None:
    match = re.fullmatch(
        r'/ip address remove \[find address="([0-9.]+/\d{1,2})" interface="([A-Za-z0-9_.\-/]+)"\]',
        command.strip(),
    )
    if not match:
        return None
    return match.group(1), match.group(2)


def _mikrotik_dhcp_parts_from_commands(proposed: list[str], rollback: list[str]) -> MikroTikDhcpParts | None:
    proposed_clean = [command.strip() for command in proposed if command.strip()]
    rollback_clean = [command.strip() for command in rollback if command.strip()]
    if len(proposed_clean) != 3 or len(rollback_clean) != 3:
        return None
    pool_match = re.fullmatch(r"/ip pool add name=([A-Za-z0-9_.-]{1,64}) ranges=([0-9.]+-[0-9.]+)", proposed_clean[0])
    server_match = re.fullmatch(
        r'/ip dhcp-server add name=([A-Za-z0-9_.-]{1,64}) interface=([A-Za-z0-9_.\-/]{1,64}) address-pool=([A-Za-z0-9_.-]{1,64}) disabled=no(?: comment="([^"\n\r;`|&$\[\]]{1,64})")?',
        proposed_clean[1],
    )
    network_match = re.fullmatch(
        r"/ip dhcp-server network add address=([0-9.]+/\d{1,2}) gateway=([0-9.]+)(?: dns-server=([0-9.,]+))?",
        proposed_clean[2],
    )
    if not pool_match or not server_match or not network_match:
        return None
    pool_name, pool_range = pool_match.group(1), pool_match.group(2)
    dhcp_name, interface, address_pool, comment = (
        server_match.group(1),
        server_match.group(2),
        server_match.group(3),
        server_match.group(4),
    )
    network, gateway, dns = network_match.group(1), network_match.group(2), network_match.group(3)
    if address_pool != pool_name:
        return None
    if rollback_clean[0] != f'/ip dhcp-server remove [find name="{dhcp_name}"]':
        return None
    if rollback_clean[1] != f'/ip dhcp-server network remove [find address="{network}"]':
        return None
    if rollback_clean[2] != f'/ip pool remove [find name="{pool_name}"]':
        return None
    return MikroTikDhcpParts(
        pool_name=pool_name,
        pool_range=pool_range,
        dhcp_name=dhcp_name,
        interface=interface,
        network=network,
        gateway=gateway,
        dns=dns,
        comment=comment,
    )


def _validate_private_cidr(value: str) -> None:
    try:
        interface = ipaddress.ip_interface(value)
    except ValueError as exc:
        raise ConfigExecutionError("MikroTik address must be a valid IPv4 interface CIDR.") from exc
    if interface.version != 4 or not interface.ip.is_private:
        raise ConfigExecutionError("MikroTik address must be a private IPv4 interface CIDR.")
    if interface.network.prefixlen < 8 or interface.network.prefixlen > 32:
        raise ConfigExecutionError("MikroTik address prefix length must be between /8 and /32.")


def _validate_private_network(value: str) -> None:
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise ConfigExecutionError("MikroTik DHCP network must be a valid IPv4 CIDR.") from exc
    if network.version != 4 or not network.is_private:
        raise ConfigExecutionError("MikroTik DHCP network must be a private IPv4 CIDR.")


def _validate_gateway_in_network(gateway: str, network: str) -> None:
    try:
        gateway_ip = ipaddress.ip_address(gateway)
        network_obj = ipaddress.ip_network(network, strict=True)
    except ValueError as exc:
        raise ConfigExecutionError("MikroTik DHCP gateway/network values are invalid.") from exc
    if gateway_ip.version != 4 or gateway_ip not in network_obj:
        raise ConfigExecutionError("MikroTik DHCP gateway must be inside the planned network.")


def _validate_pool_range(pool_range: str, network: str) -> None:
    try:
        start_raw, end_raw = pool_range.split("-", 1)
        start = ipaddress.ip_address(start_raw)
        end = ipaddress.ip_address(end_raw)
        network_obj = ipaddress.ip_network(network, strict=True)
    except ValueError as exc:
        raise ConfigExecutionError("MikroTik DHCP pool range is invalid.") from exc
    if start.version != 4 or end.version != 4 or start not in network_obj or end not in network_obj:
        raise ConfigExecutionError("MikroTik DHCP pool range must be inside the planned network.")
    if int(start) > int(end):
        raise ConfigExecutionError("MikroTik DHCP pool start must be less than or equal to pool end.")


def _reject_mikrotik_unsafe_command(command: str) -> None:
    stripped = command.strip()
    if "\n" in stripped or "\r" in stripped or ";" in stripped or "$" in stripped or "`" in stripped or "|" in stripped or "&" in stripped:
        raise ConfigExecutionError("MikroTik command contains unsafe control characters.")
    lowered = stripped.lower()
    if lowered.startswith("/ip address add "):
        if _mikrotik_parts_from_proposed(stripped) is None:
            raise ConfigExecutionError("Only the exact generated `/ip address add` command is allowed.")
        return
    if lowered.startswith("/ip address remove "):
        if _mikrotik_parts_from_rollback(stripped) is None:
            raise ConfigExecutionError("Only the exact generated `/ip address remove [find ...]` rollback is allowed.")
        return
    blocked = (
        "/system",
        "/tool",
        "/file",
        "/user",
        "/password",
        "password",
        "policy",
        "fetch",
        "import",
        "export file",
        "reboot",
        "reset",
        "remove [find]",
        "set ",
        "add ",
    )
    for pattern in blocked:
        if pattern in lowered:
            raise ConfigExecutionError(f"MikroTik command blocked by safety policy: `{pattern}`.")
    raise ConfigExecutionError("Only MikroTik address add and matching address remove rollback commands are allowed.")


def _reject_mikrotik_dhcp_unsafe_command(command: str) -> None:
    stripped = command.strip()
    if "\n" in stripped or "\r" in stripped or ";" in stripped or "$" in stripped or "`" in stripped or "|" in stripped or "&" in stripped:
        raise ConfigExecutionError("MikroTik DHCP command contains unsafe control characters.")
    lowered = stripped.lower()
    blocked = (
        "/system",
        "/tool",
        "/file",
        "/user",
        "/password",
        "password",
        "policy",
        "fetch",
        "import",
        "export file",
        "reboot",
        "reset",
    )
    for pattern in blocked:
        if pattern in lowered:
            raise ConfigExecutionError(f"MikroTik DHCP command blocked by safety policy: `{pattern}`.")
    if "remove [find" in lowered and not (
        re.fullmatch(r'/ip dhcp-server remove \[find name="[A-Za-z0-9_.-]{1,64}"\]', stripped)
        or re.fullmatch(r'/ip dhcp-server network remove \[find address="[0-9.]+/\d{1,2}"\]', stripped)
        or re.fullmatch(r'/ip pool remove \[find name="[A-Za-z0-9_.-]{1,64}"\]', stripped)
    ):
        raise ConfigExecutionError("MikroTik DHCP rollback remove command is outside the generated rollback templates.")


def _allowed_proposed_command(command: str, vlan_id: int) -> bool:
    stripped = command.strip()
    return bool(
        re.fullmatch(rf"vlan {vlan_id}", stripped)
        or re.fullmatch(r"[Nn]ame [A-Za-z0-9 _-]{1,32}", stripped)
        or re.fullmatch(r"interface range [A-Za-z]+[A-Za-z0-9/ .,-]+", stripped)
        or stripped == "switchport mode access"
        or stripped == f"switchport access vlan {vlan_id}"
        or stripped == "spanning-tree portfast"
    )


def _allowed_rollback_command(command: str, vlan_id: int) -> bool:
    stripped = command.strip()
    return bool(
        re.fullmatch(r"interface range [A-Za-z]+[A-Za-z0-9/ .,-]+", stripped)
        or stripped == f"no switchport access vlan {vlan_id}"
        or stripped == "no spanning-tree portfast"
        or stripped == f"no vlan {vlan_id}"
    )


def _run_show_commands(connection, commands: tuple[str, ...]) -> str:
    chunks: list[str] = []
    for command in commands:
        output = connection.send_command(command, read_timeout=20)
        chunks.append(f"$ {command}\n{output}")
    return "\n\n".join(chunks)


def _cisco_interface_pre_check_commands() -> tuple[str, ...]:
    return CISCO_INTERFACE_PRE_CHECK_COMMANDS


def _cisco_interface_verify_commands(proposed: list[str]) -> tuple[str, ...]:
    interface = _cisco_interface_from_proposed(proposed)
    if not interface:
        return CISCO_INTERFACE_PRE_CHECK_COMMANDS
    return (
        "show interfaces status",
        "show interfaces trunk",
        "show vlan brief",
        f"show running-config interface {interface}",
    )


def _send_mikrotik_command(connection, command: str) -> str:
    return connection.send_command(command, read_timeout=20)


def _send_mikrotik_commands(connection, commands: list[str]) -> str:
    chunks: list[str] = []
    for command in commands:
        output = _send_mikrotik_command(connection, command)
        chunks.append(f"$ {command}\n{output}")
    return "\n\n".join(chunks)


def _verify_vlan_result(proposed: list[str], post_output: str) -> bool:
    vlan_id = _vlan_id_from_commands(proposed)
    if vlan_id is None:
        return False
    return re.search(rf"(^|\s){vlan_id}(\s|$)", post_output) is not None


def _verify_mikrotik_address_result(proposed: list[str], post_output: str) -> bool:
    parts = _mikrotik_parts_from_proposed(proposed[0]) if proposed else None
    if parts is None:
        return False
    address, interface, _comment = parts
    return any(address in line and interface.lower() in line.lower() for line in post_output.splitlines())


def _verify_mikrotik_dhcp_result(proposed: list[str], post_output: str) -> bool:
    status, _message = _mikrotik_dhcp_verification_status(proposed, post_output)
    return status == "verified"


def _verify_cisco_interface_result(plan_type: str, proposed: list[str], post_output: str) -> bool:
    status, _message = _cisco_interface_verification_status(plan_type, proposed, post_output)
    return status == "verified"


def _verification_status(proposed: list[str], output: str) -> tuple[str, str]:
    vlan_id = _vlan_id_from_commands(proposed)
    if vlan_id is None:
        return "verification_failed", "Could not parse expected VLAN ID."
    if re.search(rf"(^|\s){vlan_id}(\s|$)", output) is None:
        return "verification_failed", f"Expected VLAN {vlan_id} was not found in verification output."
    ports = _ports_from_commands(proposed)
    if ports and str(vlan_id) not in output:
        return "verification_failed", f"Expected VLAN {vlan_id} was not visible for requested ports."
    return "verified", f"Verification passed. VLAN {vlan_id} appears in read-only checks."


def _mikrotik_verification_status(proposed: list[str], output: str) -> tuple[str, str]:
    parts = _mikrotik_parts_from_proposed(proposed[0]) if proposed else None
    if parts is None:
        return "verification_failed", "Could not parse expected MikroTik address plan."
    address, interface, _comment = parts
    if any(address in line and interface.lower() in line.lower() for line in output.splitlines()):
        return "verified", f"Verification passed. `{address}` appears on `{interface}`."
    if address in output:
        return "verification_failed", f"`{address}` appears, but not clearly on `{interface}`."
    return "verification_failed", f"`{address}` was not found in RouterOS verification output."


def _mikrotik_dhcp_verification_status(proposed: list[str], output: str) -> tuple[str, str]:
    parts = _mikrotik_dhcp_parts_from_commands(proposed, _expected_mikrotik_dhcp_rollback_from_proposed(proposed))
    if parts is None:
        return "verification_failed", "Could not parse expected MikroTik DHCP plan."
    missing = []
    if not _routeros_name_in_output(parts.pool_name, output):
        missing.append(f"pool {parts.pool_name}")
    if not _routeros_name_in_output(parts.dhcp_name, output):
        missing.append(f"DHCP server {parts.dhcp_name}")
    if parts.network not in output:
        missing.append(f"DHCP network {parts.network}")
    if parts.pool_name not in output:
        missing.append(f"address-pool reference {parts.pool_name}")
    if missing:
        return "verification_failed", "Expected MikroTik DHCP state missing: " + ", ".join(missing) + "."
    return "verified", f"Verification passed. DHCP server `{parts.dhcp_name}`, pool `{parts.pool_name}`, and network `{parts.network}` appear in read-only checks."


def _cisco_interface_verification_status(plan_type: str, proposed: list[str], output: str) -> tuple[str, str]:
    parsed = _cisco_interface_expected_state(plan_type, proposed)
    if parsed is None:
        return "verification_failed", "Could not parse expected Cisco interface state."
    interface, vlan_id, description = parsed
    interface_section = _interface_running_config_section(interface, output)
    if not interface_section:
        return "verification_failed", f"`show running-config interface {interface}` output was not found or was empty."
    if plan_type == "cisco_interface_description":
        expected = f"description {description}"
        if expected.lower() in interface_section.lower():
            return "verified", f"Verification passed. `{interface}` has description `{description}`."
        return "verification_failed", f"Expected description `{description}` was not found on `{interface}`."
    checks = ["switchport mode access", f"switchport access vlan {vlan_id}"]
    if description:
        checks.append(f"description {description}")
    missing = [check for check in checks if check.lower() not in interface_section.lower()]
    if missing:
        return "verification_failed", f"Expected access-port state missing on `{interface}`: {', '.join(missing)}."
    return "verified", f"Verification passed. `{interface}` appears configured for access VLAN {vlan_id}."


def _rollback_verification_status(proposed: list[str], output: str) -> tuple[str, str]:
    vlan_id = _vlan_id_from_commands(proposed)
    if vlan_id is None:
        return "manual_rollback_failed", "Could not parse expected VLAN ID."
    if re.search(rf"(^|\s){vlan_id}(\s|$)", output) is not None:
        return "manual_rollback_failed", f"VLAN {vlan_id} still appears after rollback checks."
    return "manual_rollback_success", f"Manual rollback completed. VLAN {vlan_id} was not found in verification output."


def _mikrotik_rollback_verification_status(proposed: list[str], output: str) -> tuple[str, str]:
    parts = _mikrotik_parts_from_proposed(proposed[0]) if proposed else None
    if parts is None:
        return "manual_rollback_failed", "Could not parse expected MikroTik address plan."
    address, interface, _comment = parts
    if any(address in line and interface.lower() in line.lower() for line in output.splitlines()):
        return "manual_rollback_failed", f"`{address}` still appears on `{interface}` after rollback."
    return "manual_rollback_success", f"Manual rollback completed. `{address}` was not found on `{interface}`."


def _mikrotik_dhcp_rollback_verification_status(proposed: list[str], output: str) -> tuple[str, str]:
    parts = _mikrotik_dhcp_parts_from_commands(proposed, _expected_mikrotik_dhcp_rollback_from_proposed(proposed))
    if parts is None:
        return "manual_rollback_failed", "Could not parse expected MikroTik DHCP plan."
    remaining = []
    if _routeros_name_in_output(parts.pool_name, output):
        remaining.append(f"pool {parts.pool_name}")
    if _routeros_name_in_output(parts.dhcp_name, output):
        remaining.append(f"DHCP server {parts.dhcp_name}")
    if parts.network in output:
        remaining.append(f"DHCP network {parts.network}")
    if remaining:
        return "manual_rollback_failed", "Rollback state still present: " + ", ".join(remaining) + "."
    return "manual_rollback_success", f"Manual rollback completed. DHCP server `{parts.dhcp_name}`, pool `{parts.pool_name}`, and network `{parts.network}` were not found."


def _expected_mikrotik_dhcp_rollback_from_proposed(proposed: list[str]) -> list[str]:
    proposed_clean = [command.strip() for command in proposed if command.strip()]
    if len(proposed_clean) != 3:
        return []
    pool_match = re.fullmatch(r"/ip pool add name=([A-Za-z0-9_.-]{1,64}) ranges=[0-9.]+-[0-9.]+", proposed_clean[0])
    server_match = re.fullmatch(
        r'/ip dhcp-server add name=([A-Za-z0-9_.-]{1,64}) interface=[A-Za-z0-9_.\-/]{1,64} address-pool=([A-Za-z0-9_.-]{1,64}) disabled=no(?: comment="[^"\n\r;`|&$\[\]]{1,64}")?',
        proposed_clean[1],
    )
    network_match = re.fullmatch(r"/ip dhcp-server network add address=([0-9.]+/\d{1,2}) gateway=[0-9.]+(?: dns-server=[0-9.,]+)?", proposed_clean[2])
    if not pool_match or not server_match or not network_match:
        return []
    return [
        f'/ip dhcp-server remove [find name="{server_match.group(1)}"]',
        f'/ip dhcp-server network remove [find address="{network_match.group(1)}"]',
        f'/ip pool remove [find name="{pool_match.group(1)}"]',
    ]


def _routeros_name_in_output(name: str, output: str) -> bool:
    escaped = re.escape(name)
    return bool(
        re.search(rf'(^|\s)name="?{escaped}"?(\s|$)', output, flags=re.IGNORECASE | re.MULTILINE)
        or re.search(rf"(^|\s){escaped}(\s|$)", output, flags=re.IGNORECASE | re.MULTILINE)
    )


def _cisco_interface_rollback_verification_status(plan_type: str, proposed: list[str], output: str) -> tuple[str, str]:
    parsed = _cisco_interface_expected_state(plan_type, proposed)
    if parsed is None:
        return "manual_rollback_failed", "Could not parse expected Cisco interface rollback state."
    interface, vlan_id, description = parsed
    interface_section = _interface_running_config_section(interface, output)
    if not interface_section:
        return "manual_rollback_success", f"Manual rollback completed. `{interface}` running-config section was not present in output."
    if plan_type == "cisco_interface_description":
        if description and f"description {description}".lower() in interface_section.lower():
            return "manual_rollback_failed", f"Description `{description}` still appears on `{interface}` after rollback."
        return "manual_rollback_success", f"Manual rollback completed. Description `{description}` was not found on `{interface}`."
    failed_checks = []
    if vlan_id is not None and f"switchport access vlan {vlan_id}".lower() in interface_section.lower():
        failed_checks.append(f"switchport access vlan {vlan_id}")
    if description and f"description {description}".lower() in interface_section.lower():
        failed_checks.append(f"description {description}")
    if failed_checks:
        return "manual_rollback_failed", f"Rollback state still present on `{interface}`: {', '.join(failed_checks)}."
    return "manual_rollback_success", f"Manual rollback completed for `{interface}`. Previous state may not be restored if it was unknown."


def _ports_from_commands(commands: list[str]) -> str | None:
    for command in commands:
        match = re.fullmatch(r"interface range\s+(.+)", command.strip(), flags=re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def _cisco_interface_from_proposed(proposed: list[str]) -> str | None:
    if not proposed:
        return None
    return _interface_from_line(proposed[0].strip())


def _cisco_interface_expected_state(plan_type: str, proposed: list[str]) -> tuple[str, int | None, str | None] | None:
    interface = _cisco_interface_from_proposed(proposed)
    if not interface:
        return None
    vlan_id = _access_vlan_from_commands([command.strip() for command in proposed])
    description = None
    for command in proposed:
        stripped = command.strip()
        if stripped.lower().startswith("description "):
            description = stripped.split(maxsplit=1)[1]
    if plan_type == "cisco_interface_description" and description is None:
        return None
    if plan_type == "cisco_access_port" and vlan_id is None:
        return None
    return interface, vlan_id, description


def _interface_running_config_section(interface: str, output: str) -> str:
    marker = f"interface {interface}".lower()
    lines = output.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.strip().lower() == marker:
            start = index
            break
    if start is None:
        return output if marker in output.lower() else ""
    section = []
    for line in lines[start:]:
        if section and line and not line.startswith(" ") and not line.startswith("!") and line.lower().startswith("interface "):
            break
        section.append(line)
    return "\n".join(section)


def _latest_verification_log(plan: ChangePlan) -> ExecutionLog | None:
    logs = [
        log
        for log in plan.execution_logs
        if log.status in {"verified", "verification_failed"}
    ]
    if not logs:
        return None
    return max(logs, key=lambda item: item.started_at)


def _vlan_id_from_commands(commands: list[str]) -> int | None:
    for command in commands:
        match = re.fullmatch(r"vlan\s+(\d+)", command.strip(), flags=re.IGNORECASE)
        if match:
            return int(match.group(1))
    return None


def _plan_commands(value: str) -> list[str]:
    return [line.rstrip() for line in value.splitlines() if line.strip()]


def _load_plan(session, plan_id: int) -> ChangePlan:
    plan = session.scalar(
        select(ChangePlan)
        .options(
            selectinload(ChangePlan.device).selectinload(Device.credentials),
            selectinload(ChangePlan.approval_logs),
            selectinload(ChangePlan.execution_logs),
        )
        .where(ChangePlan.id == plan_id)
    )
    if plan is None:
        raise ConfigExecutionError(f"Change plan {plan_id} not found.")
    return plan


def _open_cisco_connection(credential: DeviceCredential):
    try:
        from netmiko import ConnectHandler
    except ImportError as exc:
        raise ConfigExecutionError("Netmiko is not installed. Run `pip install -r requirements.txt`.") from exc

    try:
        password = decrypt_secret(credential.encrypted_password)
    except CredentialSecurityError as exc:
        raise ConfigExecutionError(str(exc)) from exc

    return ConnectHandler(
        device_type="cisco_ios",
        host=credential.device.ip_address,
        username=credential.username,
        password=password,
        port=credential.port,
        timeout=10,
        conn_timeout=10,
        auth_timeout=10,
        banner_timeout=10,
    )


def _open_mikrotik_connection(credential: DeviceCredential):
    try:
        from netmiko import ConnectHandler
    except ImportError as exc:
        raise ConfigExecutionError("Netmiko is not installed. Run `pip install -r requirements.txt`.") from exc

    try:
        password = decrypt_secret(credential.encrypted_password)
    except CredentialSecurityError as exc:
        raise ConfigExecutionError(str(exc)) from exc

    return ConnectHandler(
        device_type="mikrotik_routeros",
        host=credential.device.ip_address,
        username=credential.username,
        password=password,
        port=credential.port,
        timeout=10,
        conn_timeout=10,
        auth_timeout=10,
        banner_timeout=10,
    )


def _open_connection_for_credential(credential: DeviceCredential):
    if credential.platform_hint == "mikrotik_routeros":
        return _open_mikrotik_connection(credential)
    return _open_cisco_connection(credential)
