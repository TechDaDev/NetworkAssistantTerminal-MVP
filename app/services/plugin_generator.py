from __future__ import annotations

import json
from typing import Any

import httpx
from pydantic import BaseModel, Field, ValidationError

from app.agent.skill_retriever import retrieve_relevant_skills
from app.agent.tool_retriever import retrieve_relevant_tools
from app.config import settings
from app.services.context_builder import redact_sensitive_text
from app.services.plugin_registry import save_pending_plugin


class PluginGenerationError(ValueError):
    """Raised when plugin generation fails safely."""


PLUGIN_SCHEMA_ERROR_MESSAGE = (
    "Plugin generation failed because the LLM did not return the required plugin schema.\n\n"
    "Expected fields:\n"
    "- tool_name\n"
    "- description\n"
    "- category\n"
    "- code\n\n"
    "No plugin was saved, approved, or executed."
)


class PluginDraft(BaseModel):
    tool_name: str
    version: str = "0.1.0"
    description: str
    category: str
    risk_level: str = "medium"
    input_schema: dict[str, Any] = Field(default_factory=dict)
    code: str
    raw_json: dict[str, Any] = Field(default_factory=dict)


PLUGIN_SYSTEM_PROMPT = """Generate a pure Python plugin following the required interface.
Do not import forbidden modules.
Do not access files.
Do not access environment variables.
Do not connect to network devices.
Do not execute commands.
Do not use subprocess.
Do not call external APIs.
Do not call the LLM.
Return strict JSON only.
"""


def generate_plugin_from_goal(
    user_goal: str,
    missing_tool_reason: str,
    category_hint: str | None = None,
    context: dict | None = None,
) -> PluginDraft:
    if not settings.llm_enabled:
        raise PluginGenerationError("LLM is disabled. Set LLM_ENABLED=true before generating plugins.")
    if not settings.deepseek_api_key:
        raise PluginGenerationError("DEEPSEEK_API_KEY is missing.")
    prompt = _build_prompt(user_goal, missing_tool_reason, category_hint, context)
    payload = {
        "model": settings.deepseek_model,
        "messages": [
            {"role": "system", "content": PLUGIN_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
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
            content = response.json()["choices"][0]["message"]["content"]
    except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
        raise PluginGenerationError(f"Plugin generation request failed: {exc}") from exc
    return parse_plugin_json(content)


def parse_plugin_json(content: str | dict) -> PluginDraft:
    try:
        data = json.loads(content) if isinstance(content, str) else dict(content)
    except (TypeError, json.JSONDecodeError) as exc:
        raise PluginGenerationError(PLUGIN_SCHEMA_ERROR_MESSAGE) from exc
    try:
        return PluginDraft(**data, raw_json=data)
    except ValidationError as exc:
        raise PluginGenerationError(PLUGIN_SCHEMA_ERROR_MESSAGE) from exc


def save_generated_plugin(draft: PluginDraft):
    return save_pending_plugin(
        tool_name=draft.tool_name,
        version=draft.version,
        description=draft.description,
        category=draft.category,
        risk_level=draft.risk_level,
        code=draft.code,
        source="llm_generated",
    )


def _build_prompt(user_goal: str, missing_tool_reason: str, category_hint: str | None, context: dict | None) -> str:
    tools = retrieve_relevant_tools(user_goal, limit=8)
    skills = retrieve_relevant_skills(user_goal, limit=4)
    return (
        "Create a local pure-Python plugin for Network Assistant.\n"
        "Prefer existing registered tools. Generate a plugin only for reusable planner/parser/validator/reporter/diagnostic capability gaps.\n"
        "Allowed categories: planner, parser, validator, reporter, diagnostic.\n"
        "Required interface constants: TOOL_NAME, TOOL_VERSION, TOOL_DESCRIPTION, TOOL_CATEGORY, TOOL_RISK_LEVEL, INPUT_SCHEMA, OUTPUT_SCHEMA.\n"
        "Required function: run(inputs: dict) -> dict with success, summary, data, warnings.\n"
        "Forbidden: SSH, sockets, subprocess, package install, file/env access, external APIs, recursive LLM calls, router/switch config execution.\n"
        "Allowed imports only: re, json, ipaddress, math, statistics, datetime, typing.\n\n"
        f"User goal: {redact_sensitive_text(user_goal)}\n"
        f"Missing tool reason: {redact_sensitive_text(missing_tool_reason)}\n"
        f"Category hint: {category_hint or 'choose safest'}\n"
        "Relevant existing tools:\n"
        + "\n".join(f"- {tool.tool_name}: {tool.description}" for tool in tools)
        + "\nRelevant skills:\n"
        + "\n".join(f"- {skill.metadata.skill_name}: {skill.metadata.display_name}" for skill in skills)
        + "\n"
        f"Context JSON: {json.dumps(context or {}, default=str)}\n"
    )
