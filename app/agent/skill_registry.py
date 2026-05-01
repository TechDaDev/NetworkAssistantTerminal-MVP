from __future__ import annotations

import ast
import re
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field

from app.config import BASE_DIR


SKILL_INDEX_VERSION = "1.1"
SKILLS_DIR = BASE_DIR / "skills"

_REQUIRED_FIELDS = (
    "skill_name",
    "display_name",
    "category",
    "risk_level",
    "tools",
    "triggers",
    "requires_confirmation",
    "forbidden",
)


class SkillMetadata(BaseModel):
    skill_name: str
    display_name: str
    description: str = ""
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


class SkillSummary(BaseModel):
    skill_name: str
    display_name: str
    description: str
    category: str
    risk_level: str
    tools: list[str] = Field(default_factory=list)
    triggers: list[str] = Field(default_factory=list)
    requires_confirmation: list[str] = Field(default_factory=list)
    forbidden: list[str] = Field(default_factory=list)
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


def list_skill_summaries() -> list[SkillSummary]:
    summaries: list[SkillSummary] = []
    for document in load_skill_documents():
        meta = document.metadata
        summaries.append(
            SkillSummary(
                skill_name=meta.skill_name,
                display_name=meta.display_name,
                description=meta.description,
                category=meta.category,
                risk_level=meta.risk_level,
                tools=list(meta.tools),
                triggers=list(meta.triggers),
                requires_confirmation=list(meta.requires_confirmation),
                forbidden=list(meta.forbidden),
                path=document.path,
            )
        )
    return summaries


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
    front_matter, body = _split_front_matter(text)
    data = _parse_front_matter(front_matter)
    _validate_front_matter(path, data)
    metadata = SkillMetadata(**_normalize_metadata(data, body))
    rel_path = path.relative_to(BASE_DIR).as_posix() if path.is_relative_to(BASE_DIR) else str(path)
    return SkillDocument(metadata=metadata, body=body.strip(), path=rel_path)


def _split_front_matter(text: str) -> tuple[str, str]:
    if text.startswith("---\n"):
        end = text.find("\n---", 4)
        if end == -1:
            raise ValueError("Skill front matter has no closing delimiter.")
        front_matter = text[4:end]
        body = text[end + 4 :]
        return front_matter.strip(), body.strip()
    # Transitional fallback for legacy files without explicit delimiters.
    lines = text.splitlines()
    front_lines: list[str] = []
    body_start = 0
    for idx, line in enumerate(lines):
        if line.strip().startswith("#"):
            body_start = idx
            break
        if not line.strip() and front_lines:
            body_start = idx + 1
            break
        front_lines.append(line)
    if not front_lines:
        raise ValueError("Skill file has no front matter.")
    return "\n".join(front_lines).strip(), "\n".join(lines[body_start:]).strip()


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
            elif value.startswith("[") and value.endswith("]"):
                try:
                    parsed = ast.literal_eval(value)
                    data[current_key] = parsed if isinstance(parsed, list) else [str(parsed)]
                except (SyntaxError, ValueError):
                    data[current_key] = [item.strip().strip('"') for item in value.strip("[]").split(",") if item.strip()]
            elif value:
                data[current_key] = value.strip('"')
            else:
                data[current_key] = []
    return data


def _validate_front_matter(path: Path, data: dict) -> None:
    missing = [field for field in _REQUIRED_FIELDS if field not in data]
    if missing:
        raise ValueError(f"Skill {path} is missing required fields: {', '.join(missing)}")


def _normalize_metadata(data: dict, body: str) -> dict:
    normalized = dict(data)
    for key in ("tools", "triggers", "requires_confirmation", "forbidden"):
        value = normalized.get(key, [])
        if isinstance(value, str):
            normalized[key] = [item.strip() for item in value.split(",") if item.strip()]
        elif value is None:
            normalized[key] = []
    description = str(normalized.get("description", "")).strip()
    if not description:
        first_paragraph = body.strip().split("\n\n", 1)[0].replace("\n", " ").strip()
        normalized["description"] = first_paragraph or f"Skill for {normalized.get('display_name', normalized.get('skill_name', 'network operations'))}."
    return normalized


def _tokens(text: str) -> set[str]:
    return {token for token in re.findall(r"[a-z0-9]+", text.lower()) if len(token) > 1}
