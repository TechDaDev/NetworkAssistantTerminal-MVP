from __future__ import annotations

from app.agent.skill_registry import SkillDocument, search_skills
from app.agent.tool_retriever import retrieve_relevant_tools


def retrieve_relevant_skills(user_request: str, limit: int = 4) -> list[SkillDocument]:
    tools = retrieve_relevant_tools(user_request, limit=8)
    tool_names = {tool.tool_name for tool in tools}
    documents = search_skills(user_request, limit=20)
    scored: list[tuple[int, SkillDocument]] = []
    for document in documents:
        score = 0
        metadata = document.metadata
        score += len(tool_names & set(metadata.tools)) * 10
        if any(trigger.lower() in user_request.lower() for trigger in metadata.triggers):
            score += 100
        score += len(set(metadata.tools) & tool_names)
        scored.append((score, document))
    scored.sort(key=lambda item: (-item[0], item[1].metadata.skill_name))
    return [document for _, document in scored[:limit]]
