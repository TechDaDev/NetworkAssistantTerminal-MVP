from app.agent.skill_registry import get_skill, list_skill_summaries, load_skill_documents


def test_skill_registry_loads_required_files():
    names = {skill.metadata.skill_name for skill in load_skill_documents()}

    assert {
        "network_scanning",
        "router_connection",
        "nmap_scanning",
        "ssh_readonly_collection",
        "diagnostics",
        "topology",
        "snapshots_backup",
        "cisco_operations",
        "mikrotik_operations",
        "custom_plans",
        "plugin_factory",
        "knowledge_rag",
        "lab_release",
        "safety_policy",
        "troubleshooting",
    }.issubset(names)


def test_skill_metadata_parses():
    skill = get_skill("router_connection")

    assert skill.metadata.display_name
    assert skill.metadata.description
    assert "router_connect_workflow" in skill.metadata.tools
    assert "Do not generate a plugin" in skill.body


def test_list_skill_summaries_returns_compact_metadata():
    summaries = list_skill_summaries()

    assert summaries
    assert any(summary.skill_name == "network_scanning" for summary in summaries)
    assert all(summary.description for summary in summaries)
    assert all(summary.path.startswith("skills/") for summary in summaries)
