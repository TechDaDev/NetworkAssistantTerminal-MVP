from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import httpx
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.agent.custom_plan_prompt import CUSTOM_PLAN_SYSTEM_PROMPT, build_custom_plan_prompt
from app.config import settings
from app.database import get_session, init_db
from app.models import ChangePlan, Device
from app.schemas import DiagnosticFinding
from app.services.context_builder import build_local_network_context, redact_sensitive_text
from app.services.custom_command_validator import (
    classify_commands,
    has_blocked_command,
    has_double_confirmation,
    validate_precheck_command,
    validate_verification_command,
)


class CustomPlanError(ValueError):
    """Raised when a custom generated plan is invalid or unsafe."""


class CustomPlanDraft(BaseModel):
    plan_type: str
    target_device_ip: str | None = None
    platform: str
    task_summary: str
    policy_summary: str | None = None
    risk_summary: str | None = None
    missing_inputs: list[str] = Field(default_factory=list)
    precheck_commands: list[str] = Field(default_factory=list)
    proposed_commands: list[str] = Field(default_factory=list)
    rollback_commands: list[str] = Field(default_factory=list)
    verification_commands: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    raw_json: dict[str, Any] = Field(default_factory=dict)

    @property
    def has_missing_inputs(self) -> bool:
        return bool(self.missing_inputs)


def generate_custom_plan_from_goal(
    user_goal: str,
    target_device_ip: str | None = None,
    platform: str | None = None,
    additional_context: dict | None = None,
) -> CustomPlanDraft:
    context = _build_generation_context(user_goal, target_device_ip, platform, additional_context)
    content = _call_deepseek_for_plan(user_goal, target_device_ip, platform, context)
    return parse_custom_plan_json(content)


def parse_custom_plan_json(content: str | dict) -> CustomPlanDraft:
    try:
        data = json.loads(content) if isinstance(content, str) else dict(content)
    except (TypeError, json.JSONDecodeError) as exc:
        raise CustomPlanError("DeepSeek returned invalid JSON for the custom plan.") from exc
    try:
        draft = CustomPlanDraft(**data, raw_json=data)
    except ValidationError as exc:
        raise CustomPlanError(f"DeepSeek custom plan JSON failed schema validation: {exc}") from exc
    _validate_draft_shape(draft)
    if not draft.has_missing_inputs:
        _validate_draft_commands(draft)
    return draft


def save_custom_plan(draft: CustomPlanDraft) -> ChangePlan:
    if draft.has_missing_inputs:
        raise CustomPlanError("Cannot save a custom plan until missing inputs are resolved.")
    _validate_draft_shape(draft)
    _validate_draft_commands(draft)
    init_db()
    with get_session() as session:
        device = session.scalar(
            select(Device)
            .options(selectinload(Device.credentials), selectinload(Device.command_runs))
            .where(Device.ip_address == draft.target_device_ip)
        )
        if device is None:
            raise CustomPlanError(f"Device {draft.target_device_ip} is not in inventory.")
        metadata = custom_plan_metadata(draft)
        findings = _findings_for_draft(draft, metadata)
        plan = ChangePlan(
            device=device,
            plan_type=draft.plan_type,
            title=draft.task_summary[:255],
            description=_description(draft),
            risk_level="high",
            status="draft",
            proposed_commands="\n".join(draft.proposed_commands),
            rollback_commands="\n".join(draft.rollback_commands),
            validation_findings=json.dumps([finding.model_dump(mode="json") for finding in findings]),
            custom_plan_metadata_json=json.dumps(metadata, indent=2),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(plan)
        session.commit()
        saved = session.scalar(
            select(ChangePlan)
            .options(selectinload(ChangePlan.device), selectinload(ChangePlan.approval_logs), selectinload(ChangePlan.execution_logs))
            .where(ChangePlan.id == plan.id)
        )
        if saved is None:
            raise CustomPlanError("Custom plan was saved but could not be reloaded.")
        return saved


def custom_plan_metadata(draft: CustomPlanDraft) -> dict:
    classifications = classify_commands(draft.proposed_commands + draft.rollback_commands, draft.platform, plan_comment=_plan_comment(draft))
    return {
        "generated_by": "deepseek",
        "platform": draft.platform,
        "target_device_ip": draft.target_device_ip,
        "task_summary": draft.task_summary,
        "policy_summary": draft.policy_summary,
        "risk_summary": draft.risk_summary,
        "missing_inputs": draft.missing_inputs,
        "precheck_commands": draft.precheck_commands,
        "verification_commands": draft.verification_commands,
        "warnings": draft.warnings,
        "raw_json": draft.raw_json or draft.model_dump(mode="json", exclude={"raw_json"}),
        "command_classifications": [item.model_dump(mode="json") for item in classifications],
        "requires_double_confirmation": has_double_confirmation(classifications),
        "has_blocked_commands": has_blocked_command(classifications),
    }


def metadata_for_plan(plan: ChangePlan) -> dict:
    try:
        data = json.loads(plan.custom_plan_metadata_json or "{}")
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _call_deepseek_for_plan(user_goal: str, target_device_ip: str | None, platform: str | None, context: str) -> str:
    if not settings.llm_enabled:
        raise CustomPlanError("LLM is disabled. Set LLM_ENABLED=true before generating custom plans.")
    if not settings.deepseek_api_key:
        raise CustomPlanError("DEEPSEEK_API_KEY is missing. Add it to `.env` before generating custom plans.")
    payload = {
        "model": settings.deepseek_model,
        "messages": [
            {"role": "system", "content": CUSTOM_PLAN_SYSTEM_PROMPT},
            {"role": "user", "content": build_custom_plan_prompt(redact_sensitive_text(user_goal), target_device_ip, platform, context)},
        ],
        "temperature": 0.1,
        "max_tokens": 2500,
        "response_format": {"type": "json_object"},
    }
    headers = {"Authorization": f"Bearer {settings.deepseek_api_key}", "Content-Type": "application/json"}
    try:
        with httpx.Client(timeout=45.0) as client:
            response = client.post(settings.deepseek_base_url.rstrip("/") + "/chat/completions", headers=headers, json=payload)
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
    except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
        raise CustomPlanError(f"DeepSeek custom plan request failed: {exc}") from exc


def _build_generation_context(user_goal: str, target_device_ip: str | None, platform: str | None, additional_context: dict | None) -> str:
    pieces = [build_local_network_context(user_goal)]
    if target_device_ip or platform:
        pieces.append(f"Requested target_device_ip={target_device_ip or 'unknown'} platform={platform or 'unknown'}")
    if additional_context:
        pieces.append("Additional context JSON:\n" + json.dumps(additional_context, indent=2, default=str))
    return "\n\n".join(pieces)


def _validate_draft_shape(draft: CustomPlanDraft) -> None:
    allowed = {"custom_routeros_plan": "mikrotik_routeros", "custom_cisco_plan": "cisco_ios"}
    if draft.plan_type not in allowed:
        raise CustomPlanError("Custom plan_type must be custom_routeros_plan or custom_cisco_plan.")
    if draft.platform != allowed[draft.plan_type]:
        raise CustomPlanError(f"Platform `{draft.platform}` does not match plan type `{draft.plan_type}`.")
    if not draft.has_missing_inputs and not draft.target_device_ip:
        raise CustomPlanError("target_device_ip is required when no missing inputs are present.")


def _validate_draft_commands(draft: CustomPlanDraft) -> None:
    if not draft.proposed_commands:
        raise CustomPlanError("Custom plan proposed_commands cannot be empty.")
    if not draft.rollback_commands:
        raise CustomPlanError("Custom plan rollback_commands cannot be empty.")
    if not draft.verification_commands:
        raise CustomPlanError("Custom plan verification_commands cannot be empty.")
    for command in draft.precheck_commands:
        validate_precheck_command(command, draft.platform)
    for command in draft.verification_commands:
        validate_verification_command(command, draft.platform)
    classifications = classify_commands(draft.proposed_commands + draft.rollback_commands, draft.platform, plan_comment=_plan_comment(draft))
    if has_blocked_command(classifications):
        blocked = [item.command for item in classifications if item.category == "blocked_security_abuse"]
        raise CustomPlanError("Generated plan contains blocked commands: " + "; ".join(blocked))


def _findings_for_draft(draft: CustomPlanDraft, metadata: dict) -> list[DiagnosticFinding]:
    findings = [
        DiagnosticFinding(
            severity="medium" if metadata.get("requires_double_confirmation") else "info",
            title="Custom DeepSeek-generated plan",
            detail=draft.policy_summary or "Generated custom plan requires human review, backup, confirmation, and preflight.",
            evidence=[draft.risk_summary or "High-impact custom network plan."],
        )
    ]
    for warning in draft.warnings:
        findings.append(DiagnosticFinding(severity="medium", title="Generated plan warning", detail=warning))
    return findings


def _description(draft: CustomPlanDraft) -> str:
    parts = [
        "DeepSeek-generated custom network command plan.",
        f"Policy: {draft.policy_summary or '--'}",
        f"Risk: {draft.risk_summary or '--'}",
        "Backup snapshot is mandatory before execution.",
    ]
    return "\n".join(parts)


def _plan_comment(draft: CustomPlanDraft) -> str | None:
    for command in draft.proposed_commands + draft.rollback_commands:
        match = re_search_plan_comment(command)
        if match:
            return match
    return None


def re_search_plan_comment(command: str) -> str | None:
    import re

    match = re.search(r"NA-PLAN-[A-Za-z0-9_-]+", command)
    return match.group(0) if match else None
