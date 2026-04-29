from pathlib import Path


def test_release_docs_exist():
    for path in (
        "docs/RELEASE_CHECKLIST.md",
        "docs/SAFETY_MODEL.md",
        "docs/SUPPORTED_OPERATIONS.md",
    ):
        assert Path(path).exists()


def test_supported_operations_documents_boundaries():
    text = Path("docs/SUPPORTED_OPERATIONS.md").read_text(encoding="utf-8")

    assert "Supported Controlled Execution" in text
    assert "Arbitrary SSH commands" in text
    assert "LLM-generated command execution" in text


def test_safety_model_documents_gates():
    text = Path("docs/SAFETY_MODEL.md").read_text(encoding="utf-8")

    assert "approval" in text.lower()
    assert "preflight" in text.lower()
    assert "snapshots" in text.lower()
    assert "exact confirmation" in text.lower()
