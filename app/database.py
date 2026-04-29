from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from app.config import BASE_DIR, settings
from app.models import Base


def _ensure_data_dir() -> None:
    (BASE_DIR / "data").mkdir(parents=True, exist_ok=True)


_ensure_data_dir()
engine = create_engine(settings.database_url, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def init_db() -> None:
    _ensure_data_dir()
    Base.metadata.create_all(bind=engine)
    _run_lightweight_migrations()


def _run_lightweight_migrations() -> None:
    """Apply small SQLite schema upgrades for local development databases."""
    if engine.dialect.name != "sqlite":
        return

    inspector = inspect(engine)
    table_names = inspector.get_table_names()
    if "agent_action_logs" not in table_names:
        Base.metadata.tables["agent_action_logs"].create(bind=engine, checkfirst=True)
    if "device_config_snapshots" not in table_names:
        Base.metadata.tables["device_config_snapshots"].create(bind=engine, checkfirst=True)
    for table_name in (
        "topology_snapshots",
        "topology_nodes",
        "topology_edges",
        "manual_topology_nodes",
        "manual_topology_edges",
        "manual_topology_notes",
    ):
        if table_name not in table_names:
            Base.metadata.tables[table_name].create(bind=engine, checkfirst=True)
    if "change_plans" not in table_names:
        return

    existing_columns = {column["name"] for column in inspector.get_columns("change_plans")}
    statements: list[str] = []
    if "preflight_status" not in existing_columns:
        statements.append(
            "ALTER TABLE change_plans ADD COLUMN preflight_status VARCHAR(30) DEFAULT 'not_run'"
        )
    if "preflight_checked_at" not in existing_columns:
        statements.append("ALTER TABLE change_plans ADD COLUMN preflight_checked_at DATETIME")
    if "preflight_summary" not in existing_columns:
        statements.append("ALTER TABLE change_plans ADD COLUMN preflight_summary TEXT")
    if "device_config_snapshots" in inspector.get_table_names():
        snapshot_columns = {column["name"] for column in inspector.get_columns("device_config_snapshots")}
        if "plan_id" not in snapshot_columns:
            statements.append("ALTER TABLE device_config_snapshots ADD COLUMN plan_id INTEGER")
        if "execution_log_id" not in snapshot_columns:
            statements.append("ALTER TABLE device_config_snapshots ADD COLUMN execution_log_id INTEGER")
        if "platform" not in snapshot_columns:
            statements.append("ALTER TABLE device_config_snapshots ADD COLUMN platform VARCHAR(100)")
        if "command_outputs_json" not in snapshot_columns:
            statements.append("ALTER TABLE device_config_snapshots ADD COLUMN command_outputs_json TEXT DEFAULT '{}'")
    if "device_knowledge" in inspector.get_table_names():
        knowledge_columns = {column["name"] for column in inspector.get_columns("device_knowledge")}
        if "doc_type" not in knowledge_columns:
            statements.append("ALTER TABLE device_knowledge ADD COLUMN doc_type VARCHAR(100) DEFAULT 'vendor_note'")
        if "tags" not in knowledge_columns:
            statements.append("ALTER TABLE device_knowledge ADD COLUMN tags TEXT DEFAULT ''")
        if "content_hash" not in knowledge_columns:
            statements.append("ALTER TABLE device_knowledge ADD COLUMN content_hash VARCHAR(64) DEFAULT ''")
        if "source_name" not in knowledge_columns:
            statements.append("ALTER TABLE device_knowledge ADD COLUMN source_name VARCHAR(255)")
        if "is_trusted" not in knowledge_columns:
            statements.append("ALTER TABLE device_knowledge ADD COLUMN is_trusted BOOLEAN DEFAULT 0")
        if "last_used_at" not in knowledge_columns:
            statements.append("ALTER TABLE device_knowledge ADD COLUMN last_used_at DATETIME")

    if not statements:
        return

    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))
        connection.execute(text("UPDATE device_knowledge SET content_hash = '' WHERE content_hash IS NULL"))
        if "device_config_snapshots" in inspector.get_table_names():
            connection.execute(
                text("UPDATE device_config_snapshots SET command_outputs_json = '{}' WHERE command_outputs_json IS NULL")
            )


def drop_db() -> None:
    Base.metadata.drop_all(bind=engine)


def get_session() -> Session:
    init_db()
    return SessionLocal()


def database_file_path() -> Path | None:
    prefix = "sqlite:///"
    if settings.database_url.startswith(prefix):
        return Path(settings.database_url.removeprefix(prefix))
    return None
