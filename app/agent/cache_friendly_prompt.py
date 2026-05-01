from __future__ import annotations

import json

from app.agent.domain_guard import decide_network_domain
from app.agent.skill_prompt_catalog import build_skill_catalog_xml
from app.agent.skill_registry import SKILL_INDEX_VERSION, list_skill_summaries
from app.agent.skill_retriever import retrieve_relevant_skills
from app.agent.task_chainer import build_task_chain
from app.agent.tool_capability_index import TOOL_CAPABILITY_INDEX_VERSION, list_tool_capabilities
from app.agent.tool_retriever import retrieve_relevant_tools


def build_static_agent_prompt() -> str:
    tools = [tool.model_dump(mode="json") for tool in sorted(list_tool_capabilities(), key=lambda item: item.tool_name)]
    skills = [summary.model_dump(mode="json") for summary in list_skill_summaries()]
    return "\n".join(
        [
            "You are Network Assistant's planner for local network operations.",
            f"TOOL_CAPABILITY_INDEX_VERSION: {TOOL_CAPABILITY_INDEX_VERSION}",
            f"SKILL_INDEX_VERSION: {SKILL_INDEX_VERSION}",
            "Rules:",
            "- Prefer existing registered tools.",
            "- If existing tools can satisfy the request, do not generate a plugin.",
            "- For advanced Cisco IOS or MikroTik RouterOS configuration, prefer custom ChangePlan generation before plugin generation.",
            "- Use plugin generation only when a reusable planner/parser/validator/reporter/diagnostic tool is required or explicitly requested.",
            "- Do not plan public scanning, raw SSH, shell execution, credential abuse, or direct device changes outside governed workflows.",
            "Output JSON schema: {\"selected_tool\": str, \"reason\": str, \"required_inputs\": list[str], \"followup_tools\": list[str], \"risk_level\": str}",
            "Tool capability index JSON:",
            json.dumps(tools, sort_keys=True, separators=(",", ":")),
            "Skill metadata index JSON:",
            json.dumps(skills, sort_keys=True, separators=(",", ":")),
        ]
    )


def build_dynamic_agent_context(user_request: str, session_context: dict) -> str:
    domain = decide_network_domain(user_request)
    tools = retrieve_relevant_tools(user_request)
    skills = retrieve_relevant_skills(user_request)
    selected = tools[0].tool_name if tools else ""
    chain = build_task_chain(user_request, selected) if selected else []
    skill_catalog = build_skill_catalog_xml(skills)
    body = {
        "user_request": user_request,
        "domain_decision": domain.model_dump(mode="json"),
        "session_context": session_context,
        "relevant_tools": [tool.model_dump(mode="json") for tool in tools],
        "available_skills": skill_catalog,
        "followup_tool_suggestions": chain[1:],
        "trace": {
            "static_prompt_version": f"TOOL_CAPABILITY_INDEX_VERSION {TOOL_CAPABILITY_INDEX_VERSION} / SKILL_INDEX_VERSION {SKILL_INDEX_VERSION}",
            "relevant_tools": [tool.tool_name for tool in tools],
            "relevant_skills": [skill.metadata.skill_name for skill in skills],
        },
    }
    return json.dumps(body, indent=2, sort_keys=True, default=str)


def build_llm_planner_messages(user_request: str, session_context: dict) -> list[dict]:
    return [
        {"role": "system", "content": build_static_agent_prompt()},
        {"role": "user", "content": build_dynamic_agent_context(user_request, session_context)},
    ]
