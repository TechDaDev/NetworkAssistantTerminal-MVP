from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

from app.config import BASE_DIR
from app.database import get_session, init_db
from app.models import PluginTool
from app.services.plugin_validator import TOOL_NAME_RE, PluginValidationResult, validate_plugin_file


PLUGIN_ROOT = BASE_DIR / "plugins"
PENDING_DIR = PLUGIN_ROOT / "pending"
APPROVED_DIR = PLUGIN_ROOT / "approved"
DISABLED_DIR = PLUGIN_ROOT / "disabled"


def ensure_plugin_dirs() -> None:
    for path in (PENDING_DIR, APPROVED_DIR, DISABLED_DIR, PLUGIN_ROOT / "tests"):
        path.mkdir(parents=True, exist_ok=True)


def list_plugins(status: str | None = None) -> list[PluginTool]:
    init_db()
    with get_session() as session:
        stmt = select(PluginTool).order_by(PluginTool.created_at.desc())
        if status:
            stmt = stmt.where(PluginTool.status == status)
        return list(session.scalars(stmt).all())


def get_plugin(tool_name: str) -> PluginTool | None:
    init_db()
    with get_session() as session:
        return session.scalar(select(PluginTool).where(PluginTool.tool_name == tool_name))


def save_pending_plugin(
    *,
    tool_name: str,
    version: str,
    description: str,
    category: str,
    risk_level: str,
    code: str,
    source: str = "llm_generated",
) -> PluginTool:
    ensure_plugin_dirs()
    init_db()
    if not TOOL_NAME_RE.fullmatch(tool_name):
        raise ValueError("Plugin tool_name must use lowercase letters, numbers, underscore, max 64 chars.")
    path = PENDING_DIR / f"{tool_name}.py"
    path.write_text(code, encoding="utf-8")
    validation = validate_plugin_file(path)
    validation = _enforce_metadata_match(validation, tool_name, category, risk_level)
    now = datetime.now(timezone.utc)
    with get_session() as session:
        existing = session.scalar(select(PluginTool).where(PluginTool.tool_name == tool_name))
        if existing is None:
            existing = PluginTool(tool_name=tool_name, created_at=now)
            session.add(existing)
        existing.version = version
        existing.description = description
        existing.category = category
        existing.risk_level = risk_level
        existing.status = "pending"
        existing.file_path = str(path)
        existing.source = source
        existing.validation_status = validation.status
        existing.validation_report = validation.report
        existing.updated_at = now
        existing.approved_at = None
        existing.disabled_at = None
        session.commit()
        session.refresh(existing)
        return existing


def _enforce_metadata_match(validation: PluginValidationResult, tool_name: str, category: str, risk_level: str) -> PluginValidationResult:
    errors = list(validation.errors)
    metadata = validation.metadata
    if metadata.get("tool_name") and metadata["tool_name"] != tool_name:
        errors.append("TOOL_NAME must match generated plugin metadata.")
    if metadata.get("category") and metadata["category"] != category:
        errors.append("TOOL_CATEGORY must match generated plugin metadata.")
    if metadata.get("risk_level") and metadata["risk_level"] != risk_level:
        errors.append("TOOL_RISK_LEVEL must match generated plugin metadata.")
    if not errors:
        return validation
    report_lines = ["Validation failed."]
    report_lines.extend(f"ERROR: {error}" for error in errors)
    report_lines.extend(f"WARNING: {warning}" for warning in validation.warnings)
    return PluginValidationResult(
        ok=False,
        status="failed",
        report="\n".join(report_lines),
        errors=errors,
        warnings=validation.warnings,
        metadata=metadata,
    )


def validate_plugin(tool_name: str) -> PluginTool:
    init_db()
    with get_session() as session:
        plugin = session.scalar(select(PluginTool).where(PluginTool.tool_name == tool_name))
        if plugin is None:
            raise ValueError(f"Plugin `{tool_name}` not found.")
        validation = validate_plugin_file(plugin.file_path)
        plugin.validation_status = validation.status
        plugin.validation_report = validation.report
        plugin.updated_at = datetime.now(timezone.utc)
        session.commit()
        session.refresh(plugin)
        return plugin


def approve_plugin(tool_name: str) -> PluginTool:
    ensure_plugin_dirs()
    init_db()
    with get_session() as session:
        plugin = session.scalar(select(PluginTool).where(PluginTool.tool_name == tool_name))
        if plugin is None:
            raise ValueError(f"Plugin `{tool_name}` not found.")
        validation = validate_plugin_file(plugin.file_path)
        if not validation.ok:
            plugin.validation_status = "failed"
            plugin.validation_report = validation.report
            session.commit()
            raise ValueError("Plugin validation must pass before approval.")
        target = APPROVED_DIR / f"{plugin.tool_name}.py"
        shutil.move(plugin.file_path, target)
        now = datetime.now(timezone.utc)
        plugin.file_path = str(target)
        plugin.status = "approved"
        plugin.validation_status = "passed"
        plugin.validation_report = validation.report
        plugin.approved_at = now
        plugin.disabled_at = None
        plugin.updated_at = now
        session.commit()
        session.refresh(plugin)
        return plugin


def reject_plugin(tool_name: str) -> PluginTool:
    return _set_status(tool_name, "rejected")


def disable_plugin(tool_name: str) -> PluginTool:
    ensure_plugin_dirs()
    init_db()
    with get_session() as session:
        plugin = session.scalar(select(PluginTool).where(PluginTool.tool_name == tool_name))
        if plugin is None:
            raise ValueError(f"Plugin `{tool_name}` not found.")
        if Path(plugin.file_path).exists():
            target = DISABLED_DIR / f"{plugin.tool_name}.py"
            shutil.move(plugin.file_path, target)
            plugin.file_path = str(target)
        plugin.status = "disabled"
        plugin.disabled_at = datetime.now(timezone.utc)
        plugin.updated_at = datetime.now(timezone.utc)
        session.commit()
        session.refresh(plugin)
        return plugin


def register_approved_plugins_with_agent() -> dict[str, PluginTool]:
    return {plugin.tool_name: plugin for plugin in list_plugins(status="approved")}


def _set_status(tool_name: str, status: str) -> PluginTool:
    init_db()
    with get_session() as session:
        plugin = session.scalar(select(PluginTool).where(PluginTool.tool_name == tool_name))
        if plugin is None:
            raise ValueError(f"Plugin `{tool_name}` not found.")
        plugin.status = status
        plugin.updated_at = datetime.now(timezone.utc)
        session.commit()
        session.refresh(plugin)
        return plugin
