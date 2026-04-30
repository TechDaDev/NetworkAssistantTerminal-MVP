from __future__ import annotations

from app.models import ChangePlan
from app.services.custom_command_validator import classify_commands, has_blocked_command, has_double_confirmation
from app.services.custom_plan_generator import metadata_for_plan


DOUBLE_CONFIRMATION_PHRASE = "I UNDERSTAND THIS MAY DISCONNECT THE NETWORK"


def custom_plan_platform(plan: ChangePlan) -> str:
    metadata = metadata_for_plan(plan)
    return str(metadata.get("platform") or ("mikrotik_routeros" if plan.plan_type == "custom_routeros_plan" else "cisco_ios"))


def custom_plan_precheck_commands(plan: ChangePlan) -> list[str]:
    return [str(command) for command in metadata_for_plan(plan).get("precheck_commands", [])]


def custom_plan_verification_commands(plan: ChangePlan) -> list[str]:
    return [str(command) for command in metadata_for_plan(plan).get("verification_commands", [])]


def custom_plan_requires_double_confirmation(plan: ChangePlan) -> bool:
    metadata = metadata_for_plan(plan)
    if metadata.get("requires_double_confirmation") is True:
        return True
    platform = custom_plan_platform(plan)
    commands = [line.strip() for line in (plan.proposed_commands + "\n" + plan.rollback_commands).splitlines() if line.strip()]
    return has_double_confirmation(classify_commands(commands, platform))


def custom_plan_has_blocked_commands(plan: ChangePlan) -> bool:
    platform = custom_plan_platform(plan)
    commands = [line.strip() for line in (plan.proposed_commands + "\n" + plan.rollback_commands).splitlines() if line.strip()]
    return has_blocked_command(classify_commands(commands, platform))
