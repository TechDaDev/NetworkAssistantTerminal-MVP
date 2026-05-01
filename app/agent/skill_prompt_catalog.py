from __future__ import annotations

from xml.sax.saxutils import escape

from app.agent.skill_registry import SkillDocument


def build_skill_catalog_xml(skills: list[SkillDocument]) -> str:
    lines = ["<available_skills>"]
    for skill in skills:
        metadata = skill.metadata
        lines.extend(
            [
                "  <skill>",
                f"    <name>{escape(metadata.skill_name)}</name>",
                f"    <description>{escape(metadata.description)}</description>",
                f"    <category>{escape(metadata.category)}</category>",
                f"    <risk_level>{escape(metadata.risk_level)}</risk_level>",
                f"    <location>{escape(skill.path)}</location>",
                "  </skill>",
            ]
        )
    lines.append("</available_skills>")
    return "\n".join(lines)
