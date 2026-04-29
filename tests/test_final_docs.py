from pathlib import Path


FINAL_DOCS = (
    "docs/USER_GUIDE.md",
    "docs/AGENT_MODE.md",
    "docs/CHANGE_WORKFLOW.md",
    "docs/TROUBLESHOOTING.md",
    "docs/V1_RELEASE_NOTES.md",
)


def test_required_final_docs_exist():
    for path in FINAL_DOCS:
        assert Path(path).exists()


def test_change_workflow_doc_contains_lifecycle():
    text = Path("docs/CHANGE_WORKFLOW.md").read_text(encoding="utf-8")

    assert "plan -> review -> approve -> preflight -> execute -> verify -> save/rollback" in text


def test_agent_mode_doc_mentions_workflows_and_blocked_actions():
    text = Path("docs/AGENT_MODE.md").read_text(encoding="utf-8")

    assert "workflow scan and diagnose" in text
    assert "Execution/save/rollback require direct CLI exact confirmation" in text
