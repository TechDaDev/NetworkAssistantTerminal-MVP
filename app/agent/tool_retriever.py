from __future__ import annotations

import re

from app.agent.tool_capability_index import ToolCapability, list_tool_capabilities


def retrieve_relevant_tools(user_request: str, limit: int = 8) -> list[ToolCapability]:
    query = _tokens(user_request)
    lowered = " ".join(user_request.lower().split())
    scored: list[tuple[int, ToolCapability]] = []
    for tool in list_tool_capabilities():
        score = 0
        for phrase in tool.user_phrases:
            phrase_l = phrase.lower()
            if phrase_l and phrase_l in lowered:
                score += 100 + len(phrase_l.split()) * 4
        haystack = " ".join(
            [
                tool.tool_name.replace("_", " "),
                tool.display_name,
                tool.description,
                tool.category,
                " ".join(tool.required_inputs),
                " ".join(tool.optional_inputs),
                " ".join(tool.examples),
            ]
        )
        overlap = query & _tokens(haystack)
        score += len(overlap) * 8
        if "router" in query and tool.category in {"ssh_readonly", "inventory"}:
            score += 12
        if {"scan", "discover", "devices"} & query and tool.category in {"scan", "inventory"}:
            score += 12
        if {"configure", "config", "nat", "route", "firewall", "failover", "balancing"} & query and tool.category in {"planning", "custom_plan"}:
            score += 18
        if {"plugin", "tool", "parser", "planner", "reusable"} & query and tool.category == "plugin":
            score += 25
        if score > 0:
            scored.append((score, tool))
    scored.sort(key=lambda item: (-item[0], item[1].tool_name))
    return [tool for _, tool in scored[:limit]]


def _tokens(text: str) -> set[str]:
    return {token for token in re.findall(r"[a-z0-9]+", text.lower()) if len(token) > 1}
