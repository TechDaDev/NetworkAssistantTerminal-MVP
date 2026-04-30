from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field

from app.config import BASE_DIR


SKILL_INDEX_VERSION = "1.0"
SKILLS_DIR = BASE_DIR / "skills"


class SkillMetadata(BaseModel):
    skill_name: str
    display_name: str
    category: str
    risk_level: str
    tools: list[str] = Field(default_factory=list)
    triggers: list[str] = Field(default_factory=list)
    requires_confirmation: list[str] = Field(default_factory=list)
    forbidden: list[str] = Field(default_factory=list)


class SkillDocument(BaseModel):
    metadata: SkillMetadata
    body: str
    path: str


@lru_cache(maxsize=1)
def load_skill_documents() -> tuple[SkillDocument, ...]:
    documents: list[SkillDocument] = []
    if not SKILLS_DIR.exists():
        return ()
    for path in sorted(SKILLS_DIR.glob("*.skill.md")):
        documents.append(_load_skill(path))
    return tuple(sorted(documents, key=lambda doc: doc.metadata.skill_name))


def get_skill(skill_name: str) -> SkillDocument:
    for document in load_skill_documents():
        if document.metadata.skill_name == skill_name:
            return document
    raise KeyError(f"Skill `{skill_name}` not found.")


def search_skills(query: str, limit: int = 5) -> list[SkillDocument]:
    query_tokens = _tokens(query)
    lowered = query.lower()
    scored: list[tuple[int, SkillDocument]] = []
    for document in load_skill_documents():
        metadata = document.metadata
        score = 0
        for trigger in metadata.triggers:
            if trigger.lower() in lowered:
                score += 100 + len(trigger.split()) * 4
        haystack = " ".join(
            [
                metadata.skill_name.replace("_", " "),
                metadata.display_name,
                metadata.category,
                " ".join(metadata.tools),
                " ".join(metadata.triggers),
                document.body,
            ]
        )
        score += len(query_tokens & _tokens(haystack)) * 6
        if score > 0:
            scored.append((score, document))
    scored.sort(key=lambda item: (-item[0], item[1].metadata.skill_name))
    return [document for _, document in scored[:limit]]


def _load_skill(path: Path) -> SkillDocument:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise ValueError(f"Skill {path} is missing YAML front matter.")
    _, front_matter, body = text.split("---", 2)
    metadata = SkillMetadata(**_parse_front_matter(front_matter))
    return SkillDocument(metadata=metadata, body=body.strip(), path=str(path))


def _parse_front_matter(text: str) -> dict:
    data: dict[str, object] = {}
    current_key: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            continue
        if line.startswith("  - ") and current_key:
            data.setdefault(current_key, [])
            assert isinstance(data[current_key], list)
            data[current_key].append(line[4:].strip().strip('"'))
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            current_key = key.strip()
            value = value.strip()
            if value == "[]":
                data[current_key] = []
            elif value:
                data[current_key] = value.strip('"')
            else:
                data[current_key] = []
    return data


def _tokens(text: str) -> set[str]:
    return {token for token in re.findall(r"[a-z0-9]+", text.lower()) if len(token) > 1}
