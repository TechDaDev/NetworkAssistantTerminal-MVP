from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path


ALLOWED_CATEGORIES = {"planner", "parser", "validator", "reporter", "diagnostic"}
ALLOWED_RISK_LEVELS = {"low", "medium", "high"}
ALLOWED_IMPORTS = {"re", "json", "ipaddress", "math", "statistics", "datetime", "typing"}
FORBIDDEN_IMPORTS = {
    "os", "sys", "subprocess", "socket", "requests", "httpx", "urllib", "pathlib", "shutil",
    "importlib", "builtins", "pickle", "marshal", "ctypes", "multiprocessing", "threading",
    "asyncio", "paramiko", "netmiko", "scrapli", "napalm", "scapy", "nmap", "sqlalchemy",
}
FORBIDDEN_CALLS = {"open", "eval", "exec", "compile", "__import__", "globals", "locals", "vars", "input"}
REQUIRED_CONSTANTS = {
    "TOOL_NAME", "TOOL_VERSION", "TOOL_DESCRIPTION", "TOOL_CATEGORY", "TOOL_RISK_LEVEL",
    "INPUT_SCHEMA", "OUTPUT_SCHEMA",
}
TOOL_NAME_RE = re.compile(r"^[a-z0-9_]{1,64}$")
MAX_PLUGIN_BYTES = 20 * 1024


@dataclass
class PluginValidationResult:
    ok: bool
    status: str
    report: str
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


def validate_plugin_file(path: str | Path) -> PluginValidationResult:
    plugin_path = Path(path)
    errors: list[str] = []
    warnings: list[str] = []
    metadata: dict = {}
    if not plugin_path.exists():
        return _result(["Plugin file does not exist."], warnings, metadata)
    raw = plugin_path.read_bytes()
    if len(raw) > MAX_PLUGIN_BYTES:
        errors.append("Plugin file exceeds 20 KB size limit.")
    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError:
        return _result(["Plugin file is not valid UTF-8."], warnings, metadata)
    try:
        tree = ast.parse(source, filename=str(plugin_path))
    except SyntaxError as exc:
        return _result([f"Python syntax error: {exc}"], warnings, metadata)

    constants = _literal_constants(tree)
    missing = sorted(REQUIRED_CONSTANTS - set(constants))
    if missing:
        errors.append("Missing required constants: " + ", ".join(missing))
    run_functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run"]
    if not run_functions:
        errors.append("Missing required run(inputs: dict) function.")
    elif not _has_valid_run_signature(run_functions[0]):
        errors.append("run must accept exactly one argument named inputs.")
    tool_name = constants.get("TOOL_NAME")
    category = constants.get("TOOL_CATEGORY")
    risk = constants.get("TOOL_RISK_LEVEL")
    if isinstance(tool_name, str):
        metadata["tool_name"] = tool_name
        if not TOOL_NAME_RE.fullmatch(tool_name):
            errors.append("TOOL_NAME must use lowercase letters, numbers, underscore, max 64 chars.")
    if isinstance(category, str):
        metadata["category"] = category
        if category not in ALLOWED_CATEGORIES:
            errors.append(f"TOOL_CATEGORY `{category}` is not allowed.")
    if isinstance(risk, str):
        metadata["risk_level"] = risk
        if risk not in ALLOWED_RISK_LEVELS:
            errors.append(f"TOOL_RISK_LEVEL `{risk}` is not allowed.")
    for name in ("TOOL_VERSION", "TOOL_DESCRIPTION"):
        if isinstance(constants.get(name), str):
            metadata[name.lower()] = constants[name]
    if not isinstance(constants.get("INPUT_SCHEMA"), dict):
        errors.append("INPUT_SCHEMA must be a literal dict.")
    if not isinstance(constants.get("OUTPUT_SCHEMA"), dict):
        errors.append("OUTPUT_SCHEMA must be a literal dict.")

    errors.extend(_import_errors(tree))
    errors.extend(_call_errors(tree))
    errors.extend(_top_level_errors(tree))
    return _result(errors, warnings, metadata)


def _literal_constants(tree: ast.Module) -> dict:
    constants: dict = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                constants[node.targets[0].id] = ast.literal_eval(node.value)
            except Exception:
                constants[node.targets[0].id] = None
    return constants


def _has_valid_run_signature(node: ast.FunctionDef) -> bool:
    args = node.args
    return (
        len(args.args) == 1
        and args.args[0].arg == "inputs"
        and not args.vararg
        and not args.kwarg
        and not args.kwonlyargs
        and not args.defaults
    )


def _import_errors(tree: ast.Module) -> list[str]:
    errors: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                if root in FORBIDDEN_IMPORTS or root not in ALLOWED_IMPORTS:
                    errors.append(f"Import `{alias.name}` is not allowed.")
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".", 1)[0]
            if root in FORBIDDEN_IMPORTS or root not in ALLOWED_IMPORTS:
                errors.append(f"Import from `{node.module}` is not allowed.")
    return errors


def _call_errors(tree: ast.Module) -> list[str]:
    errors: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else None
            if name in FORBIDDEN_CALLS:
                errors.append(f"Call `{name}()` is not allowed.")
    return errors


def _top_level_errors(tree: ast.Module) -> list[str]:
    errors: list[str] = []
    allowed = (ast.Assign, ast.FunctionDef, ast.Import, ast.ImportFrom)
    for node in tree.body:
        if not isinstance(node, allowed):
            errors.append(f"Top-level `{type(node).__name__}` is not allowed.")
    return errors


def _result(errors: list[str], warnings: list[str], metadata: dict) -> PluginValidationResult:
    ok = not errors
    report_lines = ["Validation passed." if ok else "Validation failed."]
    report_lines.extend(f"ERROR: {error}" for error in errors)
    report_lines.extend(f"WARNING: {warning}" for warning in warnings)
    return PluginValidationResult(ok=ok, status="passed" if ok else "failed", report="\n".join(report_lines), errors=errors, warnings=warnings, metadata=metadata)
