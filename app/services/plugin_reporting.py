from __future__ import annotations

from app.models import PluginTool
from app.services.plugin_runner import PluginRunResult


def plugin_to_dict(plugin: PluginTool | None) -> dict | None:
    if plugin is None:
        return None
    return {
        "id": plugin.id,
        "tool_name": plugin.tool_name,
        "version": plugin.version,
        "description": plugin.description,
        "category": plugin.category,
        "risk_level": plugin.risk_level,
        "status": plugin.status,
        "file_path": plugin.file_path,
        "source": plugin.source,
        "validation_status": plugin.validation_status,
        "validation_report": plugin.validation_report,
        "created_at": str(plugin.created_at) if plugin.created_at else None,
        "updated_at": str(plugin.updated_at) if plugin.updated_at else None,
        "approved_at": str(plugin.approved_at) if plugin.approved_at else None,
        "disabled_at": str(plugin.disabled_at) if plugin.disabled_at else None,
    }


def plugin_run_to_dict(result: PluginRunResult) -> dict:
    return {
        "tool_name": result.tool_name,
        "success": result.success,
        "summary": result.summary,
        "data": result.data,
        "warnings": result.warnings,
    }
