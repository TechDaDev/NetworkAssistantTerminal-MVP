from app.agent.skill_prompt_catalog import build_skill_catalog_xml
from app.agent.skill_registry import load_skill_documents


def test_build_skill_catalog_xml_includes_required_fields():
    skills = list(load_skill_documents())

    xml = build_skill_catalog_xml(skills)

    assert "<available_skills>" in xml
    assert "<name>network_scanning</name>" in xml
    assert "<description>" in xml
    assert "<category>scan</category>" in xml
    assert "<risk_level>medium</risk_level>" in xml
    assert "<location>skills/network_scanning.skill.md</location>" in xml
