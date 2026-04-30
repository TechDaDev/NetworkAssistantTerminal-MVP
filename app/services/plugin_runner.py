from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path

from app.services.plugin_registry import get_plugin
from app.services.plugin_validator import validate_plugin_file
from app.services.custom_plan_generator import CustomPlanDraft, save_custom_plan


@dataclass
class PluginRunResult:
    success: bool
    summary: str
    data: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    tool_name: str = ""


def run_plugin(tool_name: str, inputs: dict) -> PluginRunResult:
    plugin = get_plugin(tool_name)
    if plugin is None:
        raise ValueError(f"Plugin `{tool_name}` not found.")
    if plugin.status != "approved":
        raise ValueError("Only approved plugins can run.")
    validation = validate_plugin_file(plugin.file_path)
    if not validation.ok:
        raise ValueError("Plugin validation failed before run: " + validation.report)
    module = _load_module(Path(plugin.file_path), tool_name)
    try:
        output = module.run(dict(inputs))
    except Exception as exc:
        raise ValueError(f"Plugin `{tool_name}` failed: {exc}") from exc
    _validate_output(output)
    return PluginRunResult(
        success=bool(output["success"]),
        summary=str(output["summary"]),
        data=dict(output["data"]),
        warnings=[str(item) for item in output["warnings"]],
        tool_name=tool_name,
    )


def _load_module(path: Path, tool_name: str):
    spec = importlib.util.spec_from_file_location(f"na_plugin_{tool_name}", path)
    if spec is None or spec.loader is None:
        raise ValueError(f"Could not load plugin `{tool_name}`.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _validate_output(output: object) -> None:
    if not isinstance(output, dict):
        raise ValueError("Plugin output must be a dict.")
    required = {"success": bool, "summary": str, "data": dict, "warnings": list}
    for key, expected_type in required.items():
        if key not in output:
            raise ValueError(f"Plugin output missing `{key}`.")
        if not isinstance(output[key], expected_type):
            raise ValueError(f"Plugin output `{key}` must be {expected_type.__name__}.")


def save_planner_output_as_change_plan(result: PluginRunResult):
    data = result.data
    platform = data.get("platform")
    plan_type = "custom_routeros_plan" if platform == "mikrotik_routeros" else "custom_cisco_plan" if platform == "cisco_ios" else None
    if plan_type is None:
        raise ValueError("Planner output must include platform mikrotik_routeros or cisco_ios.")
    draft = CustomPlanDraft(
        plan_type=plan_type,
        target_device_ip=data.get("target_device_ip"),
        platform=platform,
        task_summary=result.summary,
        policy_summary=data.get("policy_summary"),
        risk_summary=data.get("risk_summary"),
        missing_inputs=[],
        precheck_commands=data.get("precheck_commands", []),
        proposed_commands=data.get("proposed_commands", []),
        rollback_commands=data.get("rollback_commands", []),
        verification_commands=data.get("verification_commands", []),
        warnings=result.warnings,
    )
    return save_custom_plan(draft)
