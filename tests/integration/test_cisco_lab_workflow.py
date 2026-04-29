from __future__ import annotations

import pytest

from app.services.config_executor import execute_change_plan, get_execution_history, rollback_change_plan, verify_change_plan
from app.services.config_planner import approve_change_plan, create_cisco_description_plan, review_change_plan, run_preflight
from app.services.credentials import save_device_credential
from app.services.device_connection import run_readonly_profile_collection, test_connection
from app.services.lab_integration import integration_env_ready, integration_env_value, upsert_lab_device
from app.services.config_snapshot import list_snapshots


pytestmark = pytest.mark.integration


def _env(name: str) -> str:
    value = integration_env_value(name)
    if not value:
        raise KeyError(name)
    return value


def test_cisco_iosv_description_workflow(allow_real_config_tests):
    ready, missing = integration_env_ready("cisco")
    if not ready:
        pytest.skip(f"Missing Cisco lab env vars: {', '.join(missing)}")

    ip = _env("LAB_CISCO_IP")
    interface = _env("LAB_CISCO_TEST_INTERFACE")
    description = os.getenv("LAB_CISCO_TEST_DESCRIPTION", "NA-LAB-TEST")
    platform = integration_env_value("LAB_CISCO_PLATFORM", "cisco_ios")
    if platform != "cisco_ios":
        pytest.skip("Cisco integration requires LAB_CISCO_PLATFORM=cisco_ios.")

    upsert_lab_device(ip, "Cisco", "Switch")
    save_device_credential(
        ip_address=ip,
        username=_env("LAB_CISCO_USERNAME"),
        password=_env("LAB_CISCO_PASSWORD"),
        platform_hint=platform,
    )

    connection = test_connection(ip)
    assert connection.success, connection.message
    collection = run_readonly_profile_collection(ip)
    assert collection.success_count > 0

    result = create_cisco_description_plan(device_ip=ip, interface=interface, description=description)
    plan_id = result.plan.id
    review_change_plan(plan_id, note="Cisco lab integration review")
    approve_change_plan(plan_id, note="Cisco lab integration approval", force=True)
    preflight = run_preflight(plan_id, refresh=True)
    assert preflight.plan.preflight_status in {"passed", "warning"}
    dry_run = execute_change_plan(plan_id, dry_run=True)
    assert dry_run.dry_run

    if not allow_real_config_tests:
        pytest.skip("ALLOW_REAL_CONFIG_TESTS=true is required for real Cisco config execution.")

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
