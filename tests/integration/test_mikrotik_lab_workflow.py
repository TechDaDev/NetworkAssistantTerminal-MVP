from __future__ import annotations

import pytest

from app.services.config_executor import execute_change_plan, get_execution_history, rollback_change_plan, verify_change_plan
from app.services.config_planner import (
    approve_change_plan,
    create_mikrotik_address_plan,
    create_mikrotik_dhcp_plan,
    review_change_plan,
    run_preflight,
)
from app.services.config_snapshot import list_snapshots
from app.services.credentials import save_device_credential
from app.services.device_connection import run_readonly_profile_collection, test_connection
from app.services.lab_integration import integration_env_ready, integration_env_value, upsert_lab_device


pytestmark = pytest.mark.integration


def _env(name: str) -> str:
    value = integration_env_value(name)
    if not value:
        raise KeyError(name)
    return value


def test_mikrotik_chr_address_workflow(allow_real_config_tests):
    ready, missing = integration_env_ready("mikrotik")
    if not ready:
        pytest.skip(f"Missing MikroTik lab env vars: {', '.join(missing)}")

    ip = _env("LAB_MIKROTIK_IP")
    platform = integration_env_value("LAB_MIKROTIK_PLATFORM", "mikrotik_routeros")
    if platform != "mikrotik_routeros":
        pytest.skip("MikroTik integration requires LAB_MIKROTIK_PLATFORM=mikrotik_routeros.")

    upsert_lab_device(ip, "MikroTik", "Router")
    save_device_credential(
        ip_address=ip,
        username=_env("LAB_MIKROTIK_USERNAME"),
        password=_env("LAB_MIKROTIK_PASSWORD"),
        platform_hint=platform,
    )

    connection = test_connection(ip)
    assert connection.success, connection.message
    collection = run_readonly_profile_collection(ip)
    assert collection.success_count > 0

    result = create_mikrotik_address_plan(
        device_ip=ip,
        interface=_env("LAB_MIKROTIK_TEST_INTERFACE"),
        address=_env("LAB_MIKROTIK_TEST_ADDRESS"),
        comment="NA LAB ADDRESS",
    )
    plan_id = result.plan.id
    review_change_plan(plan_id, note="MikroTik lab integration review")
    approve_change_plan(plan_id, note="MikroTik lab integration approval", force=True)
    preflight = run_preflight(plan_id, refresh=True)
    assert preflight.plan.preflight_status in {"passed", "warning"}
    dry_run = execute_change_plan(plan_id, dry_run=True)
    assert dry_run.dry_run

    if not allow_real_config_tests:
        pytest.skip("ALLOW_REAL_CONFIG_TESTS=true is required for real MikroTik config execution.")

    assert preflight.plan.preflight_status == "passed"
    executed = execute_change_plan(plan_id, confirmation=f"EXECUTE PLAN {plan_id}")
    assert executed.log is not None
    assert executed.log.status in {"success", "rolled_back"}
    if executed.log.status == "success":
        verified = verify_change_plan(plan_id)
        assert verified.log.status == "verified"
        rolled_back = rollback_change_plan(plan_id, confirmation=f"ROLLBACK PLAN {plan_id}")
        assert rolled_back.log.status == "manual_rollback_success"
        verify_change_plan(plan_id)

    assert get_execution_history(plan_id)
    assert list_snapshots(device_ip=ip, plan_id=plan_id)


def test_mikrotik_chr_dhcp_dry_run_workflow(allow_real_dhcp_tests):
    ready, missing = integration_env_ready("mikrotik")
    if not ready:
        pytest.skip(f"Missing MikroTik lab env vars: {', '.join(missing)}")

    ip = _env("LAB_MIKROTIK_IP")
    upsert_lab_device(ip, "MikroTik", "Router")
    save_device_credential(
        ip_address=ip,
        username=_env("LAB_MIKROTIK_USERNAME"),
        password=_env("LAB_MIKROTIK_PASSWORD"),
        platform_hint=integration_env_value("LAB_MIKROTIK_PLATFORM", "mikrotik_routeros"),
    )
    run_readonly_profile_collection(ip)

    result = create_mikrotik_dhcp_plan(
        device_ip=ip,
        name=_env("LAB_MIKROTIK_DHCP_NAME"),
        interface=_env("LAB_MIKROTIK_TEST_INTERFACE"),
        network=_env("LAB_MIKROTIK_DHCP_NETWORK"),
        gateway=_env("LAB_MIKROTIK_DHCP_GATEWAY"),
        pool_name=_env("LAB_MIKROTIK_DHCP_POOL_NAME"),
        pool_range=_env("LAB_MIKROTIK_DHCP_POOL_RANGE"),
        dns=integration_env_value("LAB_MIKROTIK_DHCP_DNS") or None,
        comment="NA LAB DHCP",
    )
    plan_id = result.plan.id
    review_change_plan(plan_id, note="MikroTik DHCP lab integration review")
    approve_change_plan(plan_id, note="MikroTik DHCP lab integration approval", force=True)
    preflight = run_preflight(plan_id, refresh=True)
    assert preflight.plan.preflight_status in {"passed", "warning"}
    dry_run = execute_change_plan(plan_id, dry_run=True)
    assert dry_run.dry_run

    if not allow_real_dhcp_tests:
        pytest.skip("ALLOW_REAL_CONFIG_TESTS=true and ALLOW_REAL_DHCP_TESTS=true are required for real DHCP execution.")

    assert preflight.plan.preflight_status == "passed"
    executed = execute_change_plan(plan_id, confirmation=f"EXECUTE PLAN {plan_id}")
    assert executed.log.status in {"success", "rolled_back"}
    if executed.log.status == "success":
        verify_change_plan(plan_id)
        rollback_change_plan(plan_id, confirmation=f"ROLLBACK PLAN {plan_id}")
