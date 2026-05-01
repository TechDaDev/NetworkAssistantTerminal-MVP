from __future__ import annotations

import json
from typing import Any

import httpx

from app.agent.agent_models import SkillPlan
from app.agent.skill_prompt_catalog import build_skill_catalog_xml
from app.agent.skill_registry import SkillDocument
from app.agent.tool_capability_index import ToolCapability
from app.agent.tool_registry import get_tool_spec
from app.config import settings


_TOOL_ALIASES: dict[str, str] = {
    "show_report": "latest_report",
    "create_cisco_vlan_plan": "create_vlan_plan",
    "custom_plan_generate": "custom_plan_goal",
    "plugin_generate": "generate_plugin_tool",
    "connect_collect_readonly": "connect_collect",
    "snapshot_capture": "capture_snapshot",
    "snapshot_list": "list_snapshots",
    "snapshot_show": "show_snapshot",
    "snapshot_export": "export_snapshot_file",
    "manual_topology_node": "add_manual_topology_node",
    "manual_topology_edge": "add_manual_topology_edge",
    "topology_report": "topology_report_file",
    "export_topology": "export_topology_file",
    "knowledge_fetch_url": "fetch_docs_url",
    "custom_plan_show": "show_plan",
    "custom_plan_review": "review_plan",
    "custom_plan_preflight": "preflight_plan",
}


def normalize_tool_name(tool_name: str) -> str:
    return _TOOL_ALIASES.get(tool_name, tool_name)


def select_skill_plan(
    user_request: str,
    session_context: dict[str, Any],
    candidate_skills: list[SkillDocument],
    candidate_tools: list[ToolCapability],
) -> SkillPlan:
    if not candidate_skills:
        return SkillPlan(selected_skill="none", selected_tool="none", reason="No candidate skills found.", confidence=0.0)

    if settings.llm_enabled and settings.deepseek_api_key:
        try:
            return _plan_with_llm(user_request, session_context, candidate_skills, candidate_tools)
        except Exception:
            # Keep agent usable even if planner LLM is unavailable.
            pass

    return _deterministic_fallback(user_request, candidate_skills, candidate_tools)


def _plan_with_llm(
    user_request: str,
    session_context: dict[str, Any],
    candidate_skills: list[SkillDocument],
    candidate_tools: list[ToolCapability],
) -> SkillPlan:
    skill_catalog_xml = build_skill_catalog_xml(candidate_skills)
    tool_catalog = [
        {
            "tool_name": tool.tool_name,
            "display_name": tool.display_name,
            "category": tool.category,
            "risk_level": tool.risk_level,
            "description": tool.description,
        }
        for tool in candidate_tools
    ]
    payload = {
        "model": settings.deepseek_model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are Network Assistant's skill planner. "
                    "Select exactly one skill from available_skills. "
                    "Select only one registered tool allowed by that skill. "
                    "Never invent skills or tools. "
                    "If no skill matches, return selected_skill=\"none\" and selected_tool=\"none\". "
                    "Prefer the most specific skill. "
                    "Do not choose plugin generation when an existing skill/tool can satisfy the request. "
                    "Respect risk and forbidden lists. "
                    "Return strict JSON only with keys: selected_skill, selected_tool, reason, required_inputs, followup_tools, risk_level, confidence."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "user_request": user_request,
                        "available_skills": skill_catalog_xml,
                        "relevant_tools": tool_catalog,
                        "session_context": session_context,
                    },
                    indent=2,
                    sort_keys=True,
                ),
            },
        ],
        "temperature": 0.0,
        "max_tokens": 400,
    }
    url = settings.deepseek_base_url.rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {settings.deepseek_api_key}",
        "Content-Type": "application/json",
    }
    with httpx.Client(timeout=15.0) as client:
        response = client.post(url, headers=headers, json=payload)
        response.raise_for_status()
    data = response.json()
    content = str(data["choices"][0]["message"]["content"])
    plan = SkillPlan.model_validate(_extract_json(content))
    return _validate_plan(plan, candidate_skills, candidate_tools)


def _extract_json(content: str) -> dict[str, Any]:
    text = content.strip()
    if text.startswith("```"):
        lines = [line for line in text.splitlines() if not line.strip().startswith("```")]
        text = "\n".join(lines).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("Planner did not return JSON.")
    return json.loads(text[start : end + 1])


def _validate_plan(plan: SkillPlan, candidate_skills: list[SkillDocument], candidate_tools: list[ToolCapability]) -> SkillPlan:
    skill_map = {skill.metadata.skill_name: skill for skill in candidate_skills}
    if plan.selected_skill not in skill_map:
        raise ValueError("Planner selected unknown skill.")

    selected_skill = skill_map[plan.selected_skill]
    normalized_tool = normalize_tool_name(plan.selected_tool)
    if not _tool_allowed_for_skill(normalized_tool, selected_skill, candidate_tools):
        raise ValueError("Planner selected tool outside selected skill.")

    if get_tool_spec(normalized_tool) is None:
        raise ValueError("Planner selected non-registered tool.")

    return SkillPlan(
        selected_skill=plan.selected_skill,
        selected_tool=normalized_tool,
        reason=plan.reason,
        required_inputs=plan.required_inputs,
        followup_tools=[normalize_tool_name(tool_name) for tool_name in plan.followup_tools],
        risk_level=plan.risk_level,
        confidence=max(0.0, min(1.0, plan.confidence)),
    )


def _deterministic_fallback(
    user_request: str,
    candidate_skills: list[SkillDocument],
    candidate_tools: list[ToolCapability],
) -> SkillPlan:
    skill = candidate_skills[0]
    for tool in candidate_tools:
        normalized_tool = normalize_tool_name(tool.tool_name)
        if _tool_allowed_for_skill(normalized_tool, skill, candidate_tools) and get_tool_spec(normalized_tool) is not None:
            return SkillPlan(
                selected_skill=skill.metadata.skill_name,
                selected_tool=normalized_tool,
                reason="Deterministic fallback selected highest-ranked matching skill/tool.",
                required_inputs=list(tool.required_inputs),
                followup_tools=[normalize_tool_name(name) for name in tool.followup_tools],
                risk_level=tool.risk_level,
                confidence=0.65,
            )

    for tool_name in getattr(skill.metadata, "tools", []):
        normalized_tool = normalize_tool_name(tool_name)
        if get_tool_spec(normalized_tool) is not None:
            return SkillPlan(
                selected_skill=skill.metadata.skill_name,
                selected_tool=normalized_tool,
                reason="Deterministic fallback selected a registered tool from the chosen skill.",
                risk_level=skill.metadata.risk_level,
                confidence=0.5,
            )

    return SkillPlan(
        selected_skill="none",
        selected_tool="none",
        reason=f"No executable tool found for skill {skill.metadata.skill_name}.",
        confidence=0.0,
    )


def _tool_allowed_for_skill(tool_name: str, skill: SkillDocument, candidate_tools: list[ToolCapability]) -> bool:
    allowed = {normalize_tool_name(name) for name in getattr(skill.metadata, "tools", [])}
    if tool_name in allowed:
        return True

    for tool in candidate_tools:
        normalized = normalize_tool_name(tool.tool_name)
        if normalized != tool_name:
            continue
        if skill.metadata.skill_name in getattr(tool, "related_skills", []) and normalized.startswith("workflow_"):
            return True

    return False
