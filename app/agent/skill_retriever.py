from __future__ import annotations

import re

from app.agent.skill_registry import SkillDocument, search_skills
from app.agent.tool_retriever import retrieve_relevant_tools


def retrieve_relevant_skills(user_request: str, limit: int = 4) -> list[SkillDocument]:
    tools = retrieve_relevant_tools(user_request, limit=8)
    tool_names = {tool.tool_name for tool in tools}
    tool_categories = {tool.category for tool in tools}
    request_tokens = _tokens(user_request)
    lowered = user_request.lower()
    documents = search_skills(user_request, limit=20)
    scored: list[tuple[int, SkillDocument]] = []
    for document in documents:
        score = 0
        metadata = document.metadata
        # a) trigger phrase match
        if any(trigger.lower() in lowered for trigger in metadata.triggers):
            score += 100

        # b) token overlap with name/display/description/triggers
        haystack = " ".join(
            [
                metadata.skill_name.replace("_", " "),
                metadata.display_name,
                metadata.description,
                metadata.category,
                " ".join(metadata.triggers),
                " ".join(metadata.tools),
            ]
        )
        score += len(request_tokens & _tokens(haystack)) * 6

        # c) related tool match
        score += len(tool_names & set(metadata.tools)) * 12

        # d) category/risk compatibility
        if metadata.category in tool_categories:
            score += 10
        if metadata.risk_level == "low" and {"show", "what", "info", "diagnose"} & request_tokens:
            score += 4
        if metadata.risk_level in {"medium", "high"} and {"configure", "plan", "workflow", "connect"} & request_tokens:
            score += 4

        scored.append((score, document))
    scored.sort(key=lambda item: (-item[0], item[1].metadata.skill_name))
    return [document for _, document in scored[:limit]]


def _tokens(text: str) -> set[str]:
    return {token for token in re.findall(r"[a-z0-9]+", text.lower()) if len(token) > 1}
