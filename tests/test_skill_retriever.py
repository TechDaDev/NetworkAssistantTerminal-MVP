from app.agent.skill_retriever import retrieve_relevant_skills


def test_connect_router_retrieves_router_skill():
    names = [skill.metadata.skill_name for skill in retrieve_relevant_skills("connect to my router")]

    assert "router_connection" in names


def test_scan_network_retrieves_network_scanning_skill():
    names = [skill.metadata.skill_name for skill in retrieve_relevant_skills("scan my network")]

    assert "network_scanning" in names
