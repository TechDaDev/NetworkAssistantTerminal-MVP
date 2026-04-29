from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import or_, select, text
from sqlalchemy.exc import SQLAlchemyError

from app.database import engine, get_session, init_db
from app.models import DeviceKnowledge


SUPPORTED_DOC_TYPES = {
    "vendor_note",
    "model_note",
    "command_reference",
    "reset_procedure",
    "connection_guide",
    "troubleshooting_note",
    "safety_note",
}
SUPPORTED_IMPORT_SUFFIXES = {".txt", ".md"}


class KnowledgeError(RuntimeError):
    """Raised when local knowledge cannot be saved or searched."""


@dataclass
class KnowledgeSearchResult:
    item: DeviceKnowledge
    rank: float | None = None
    preview: str = ""


def add_knowledge(
    title: str,
    content: str,
    vendor: str | None = None,
    model: str | None = None,
    device_type: str | None = None,
    doc_type: str = "vendor_note",
    tags: str = "",
    source_name: str | None = None,
    is_trusted: bool = False,
    source_type: str = "manual",
    source_url: str | None = None,
) -> DeviceKnowledge:
    _validate_doc_type(doc_type)
    clean_title = title.strip()
    clean_content = content.strip()
    if not clean_title:
        raise KnowledgeError("Knowledge title cannot be empty.")
    if not clean_content:
        raise KnowledgeError("Knowledge content cannot be empty.")

    init_db()
    ensure_fts_table()
    with get_session() as session:
        item = DeviceKnowledge(
            vendor=_clean_optional(vendor),
            model=_clean_optional(model),
            device_type=_clean_optional(device_type),
            doc_type=doc_type,
            tags=_normalize_tags(tags),
            content_hash=_content_hash(clean_content),
            source_name=_clean_optional(source_name),
            is_trusted=is_trusted,
            title=clean_title,
            content=clean_content,
            source_type=source_type,
            source_url=_clean_optional(source_url),
        )
        session.add(item)
        session.commit()
        session.refresh(item)
        _upsert_fts(item)
        return item


def import_knowledge_file(
    path: str,
    vendor: str | None,
    model: str | None,
    doc_type: str,
    tags: str = "",
    title: str | None = None,
    source_name: str | None = None,
    is_trusted: bool = False,
) -> DeviceKnowledge:
    file_path = Path(path).expanduser()
    if file_path.suffix.lower() not in SUPPORTED_IMPORT_SUFFIXES:
        raise KnowledgeError("Only .txt and .md files can be imported.")
    if not file_path.exists() or not file_path.is_file():
        raise KnowledgeError(f"Knowledge file not found: {file_path}")
    content = file_path.read_text(encoding="utf-8")
    return add_knowledge(
        title=title or file_path.stem.replace("_", " ").replace("-", " "),
        content=content,
        vendor=vendor,
        model=model,
        doc_type=doc_type,
        tags=tags,
        source_name=source_name or str(file_path),
        is_trusted=is_trusted,
        source_type="file",
        source_url=str(file_path),
    )


def list_knowledge() -> list[DeviceKnowledge]:
    init_db()
    with get_session() as session:
        return list(session.scalars(select(DeviceKnowledge).order_by(DeviceKnowledge.updated_at.desc())).all())


def get_knowledge(knowledge_id: int) -> DeviceKnowledge | None:
    init_db()
    with get_session() as session:
        return session.get(DeviceKnowledge, knowledge_id)


def delete_knowledge(knowledge_id: int) -> bool:
    init_db()
    ensure_fts_table()
    with get_session() as session:
        item = session.get(DeviceKnowledge, knowledge_id)
        if item is None:
            return False
        session.delete(item)
        session.commit()
    _delete_fts(knowledge_id)
    return True


def search_knowledge(query: str, limit: int = 10) -> list[KnowledgeSearchResult]:
    init_db()
    ensure_fts_table()
    if not query.strip():
        return []
    if fts_available():
        try:
            results = _search_fts(query, limit=limit)
            if results:
                return results
        except SQLAlchemyError:
            pass
    return _search_like(query, limit=limit)


def search_related_knowledge(query: str, limit: int = 3) -> list[KnowledgeSearchResult]:
    results = search_knowledge(query, limit=limit)
    now = datetime.now(timezone.utc)
    ids = [result.item.id for result in results]
    if ids:
        with get_session() as session:
            for item in session.scalars(select(DeviceKnowledge).where(DeviceKnowledge.id.in_(ids))):
                item.last_used_at = now
            session.commit()
    return results


def ensure_fts_table() -> bool:
    if engine.dialect.name != "sqlite":
        return False
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE VIRTUAL TABLE IF NOT EXISTS device_knowledge_fts "
                    "USING fts5(knowledge_id UNINDEXED, vendor, model, title, content, tags)"
                )
            )
        rebuild_fts_index()
        return True
    except SQLAlchemyError:
        return False


def fts_available() -> bool:
    if engine.dialect.name != "sqlite":
        return False
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1 FROM device_knowledge_fts LIMIT 1"))
        return True
    except SQLAlchemyError:
        return False


def rebuild_fts_index() -> None:
    with get_session() as session:
        items = list(session.scalars(select(DeviceKnowledge)).all())
    with engine.begin() as connection:
        connection.execute(text("DELETE FROM device_knowledge_fts"))
        for item in items:
            connection.execute(
                text(
                    "INSERT INTO device_knowledge_fts "
                    "(knowledge_id, vendor, model, title, content, tags) "
                    "VALUES (:knowledge_id, :vendor, :model, :title, :content, :tags)"
                ),
                _fts_params(item),
            )


def _search_fts(query: str, limit: int) -> list[KnowledgeSearchResult]:
    match_query = _fts_query(query)
    if not match_query:
        return []
    with engine.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT knowledge_id, bm25(device_knowledge_fts) AS rank, "
                "snippet(device_knowledge_fts, 4, '[', ']', ' ... ', 24) AS preview "
                "FROM device_knowledge_fts "
                "WHERE device_knowledge_fts MATCH :query "
                "ORDER BY rank LIMIT :limit"
            ),
            {"query": match_query, "limit": limit},
        ).mappings().all()
    ids = [int(row["knowledge_id"]) for row in rows]
    if not ids:
        return []
    with get_session() as session:
        items = {item.id: item for item in session.scalars(select(DeviceKnowledge).where(DeviceKnowledge.id.in_(ids)))}
    results: list[KnowledgeSearchResult] = []
    for row in rows:
        item = items.get(int(row["knowledge_id"]))
        if item is not None:
            results.append(
                KnowledgeSearchResult(
                    item=item,
                    rank=float(row["rank"]) if row["rank"] is not None else None,
                    preview=row["preview"] or _preview(item.content),
                )
            )
    return results


def _search_like(query: str, limit: int) -> list[KnowledgeSearchResult]:
    terms = [term.strip() for term in query.split() if term.strip()]
    if not terms:
        return []
    with get_session() as session:
        statement = select(DeviceKnowledge)
        for term in terms:
            pattern = f"%{term}%"
            statement = statement.where(
                or_(
                    DeviceKnowledge.vendor.ilike(pattern),
                    DeviceKnowledge.model.ilike(pattern),
                    DeviceKnowledge.device_type.ilike(pattern),
                    DeviceKnowledge.title.ilike(pattern),
                    DeviceKnowledge.content.ilike(pattern),
                    DeviceKnowledge.tags.ilike(pattern),
                )
            )
        items = list(session.scalars(statement.order_by(DeviceKnowledge.updated_at.desc()).limit(limit)).all())
    return [KnowledgeSearchResult(item=item, preview=_preview(item.content)) for item in items]


def _upsert_fts(item: DeviceKnowledge) -> None:
    if not fts_available():
        return
    with engine.begin() as connection:
        connection.execute(
            text("DELETE FROM device_knowledge_fts WHERE knowledge_id = :knowledge_id"),
            {"knowledge_id": item.id},
        )
        connection.execute(
            text(
                "INSERT INTO device_knowledge_fts "
                "(knowledge_id, vendor, model, title, content, tags) "
                "VALUES (:knowledge_id, :vendor, :model, :title, :content, :tags)"
            ),
            _fts_params(item),
        )


def _delete_fts(knowledge_id: int) -> None:
    if not fts_available():
        return
    with engine.begin() as connection:
        connection.execute(
            text("DELETE FROM device_knowledge_fts WHERE knowledge_id = :knowledge_id"),
            {"knowledge_id": knowledge_id},
        )


def _fts_params(item: DeviceKnowledge) -> dict:
    return {
        "knowledge_id": item.id,
        "vendor": item.vendor or "",
        "model": item.model or "",
        "title": item.title or "",
        "content": item.content or "",
        "tags": item.tags or "",
    }


def _fts_query(query: str) -> str:
    tokens = [token.lower() for token in re.findall(r"[A-Za-z0-9_.-]+", query) if len(token) >= 2]
    safe_tokens = [re.sub(r"[^A-Za-z0-9_]", "", token) for token in tokens]
    safe_tokens = [token for token in safe_tokens if token]
    return " OR ".join(f"{token}*" for token in safe_tokens[:8])


def _validate_doc_type(doc_type: str) -> None:
    if doc_type not in SUPPORTED_DOC_TYPES:
        allowed = ", ".join(sorted(SUPPORTED_DOC_TYPES))
        raise KnowledgeError(f"Unsupported doc_type `{doc_type}`. Allowed values: {allowed}.")


def _normalize_tags(tags: str) -> str:
    values = [tag.strip() for tag in tags.split(",") if tag.strip()]
    return ", ".join(dict.fromkeys(values))


def _clean_optional(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _preview(content: str, length: int = 240) -> str:
    compact = " ".join(content.split())
    if len(compact) <= length:
        return compact
    return compact[: length - 3] + "..."
