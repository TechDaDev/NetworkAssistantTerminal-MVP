from __future__ import annotations

import importlib.util
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import inspect

from app.config import BASE_DIR, settings
from app.database import database_file_path, engine, init_db
from app.services.lab_integration import integration_flags
from app.services.security import generate_credential_key


DISPLAY_VERSION = "1.0.0-rc1"
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8765
REQUIRED_TABLES = {
    "devices",
    "device_credentials",
    "command_runs",
    "change_plans",
    "execution_logs",
    "device_config_snapshots",
}
REQUIRED_V1_DOCS = (
    "README.md",
    "docs/SAFETY_MODEL.md",
    "docs/SUPPORTED_OPERATIONS.md",
    "docs/RELEASE_CHECKLIST.md",
    "docs/LAB_VALIDATION.md",
    "docs/INTEGRATION_TESTING.md",
    "docs/USER_GUIDE.md",
    "docs/AGENT_MODE.md",
    "docs/CHANGE_WORKFLOW.md",
    "docs/TROUBLESHOOTING.md",
    "docs/V1_RELEASE_NOTES.md",
)


@dataclass
class ReleaseCheck:
    name: str
    status: str
    detail: str
    recommendation: str | None = None


@dataclass
class ReleaseCommandResult:
    title: str
    summary: str
    checks: list[ReleaseCheck] = field(default_factory=list)
    suggested_commands: list[str] = field(default_factory=list)


def version_text() -> str:
    return f"Network Assistant\nVersion: {DISPLAY_VERSION}"


def init_project(base_dir: Path = BASE_DIR, force: bool = False) -> ReleaseCommandResult:
    data_dir = base_dir / "data"
    env_path = base_dir / ".env"
    example_path = base_dir / ".env.example"
    checks: list[ReleaseCheck] = []

    data_dir.mkdir(parents=True, exist_ok=True)
    checks.append(ReleaseCheck("Data directory", "pass", f"Ready: {data_dir}"))

    if env_path.exists() and not force:
        env_text = env_path.read_text(encoding="utf-8")
        checks.append(ReleaseCheck(".env", "pass", ".env exists and was not overwritten."))
    else:
        if env_path.exists() and force:
            checks.append(ReleaseCheck(".env force", "warning", "Existing .env was overwritten because --force was used."))
        env_text = example_path.read_text(encoding="utf-8") if example_path.exists() else ""
        env_path.write_text(env_text, encoding="utf-8")
        checks.append(ReleaseCheck(".env", "pass", f"Created from {example_path.name if example_path.exists() else 'built-in defaults'}."))

    updated_text, changed = _ensure_credential_key(env_text)
    if changed:
        env_path.write_text(updated_text, encoding="utf-8")
        checks.append(ReleaseCheck("Credential key", "pass", "Generated CREDENTIAL_SECRET_KEY in .env."))
    else:
        checks.append(ReleaseCheck("Credential key", "pass", "CREDENTIAL_SECRET_KEY is already set."))

    init_db()
    checks.append(ReleaseCheck("SQLite schema", "pass", "Database tables initialized."))

    return ReleaseCommandResult(
        title="Network Assistant Init",
        summary="Local environment initialized.",
        checks=checks,
        suggested_commands=[
            "python main.py doctor",
            "python main.py detect",
            "python main.py scan",
            "python main.py agent",
        ],
    )


def doctor() -> ReleaseCommandResult:
    checks: list[ReleaseCheck] = []
    checks.append(
        ReleaseCheck(
            "Python",
            "pass" if sys.version_info >= (3, 11) else "fail",
            f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "Use Python 3.11 or newer." if sys.version_info < (3, 11) else None,
        )
    )
    checks.append(_path_check("Project root", BASE_DIR, should_exist=True))
    checks.append(_path_check("Data directory", BASE_DIR / "data", should_exist=True))
    checks.append(_path_check(".env", BASE_DIR / ".env", should_exist=True, recommendation="python main.py init"))
    db_path = database_file_path()
    checks.append(
        ReleaseCheck(
            "Database",
            "pass" if db_path is None or db_path.exists() else "warning",
            str(db_path) if db_path else settings.database_url,
            "python main.py init" if db_path and not db_path.exists() else None,
        )
    )
    try:
        init_db()
        tables = set(inspect(engine).get_table_names())
        missing = sorted(REQUIRED_TABLES - tables)
        checks.append(
            ReleaseCheck(
                "Required tables",
                "pass" if not missing else "fail",
                "All required tables exist." if not missing else f"Missing: {', '.join(missing)}",
                "python main.py init" if missing else None,
            )
        )
    except Exception as exc:
        checks.append(ReleaseCheck("Required tables", "fail", str(exc), "python main.py init"))

    checks.append(
        ReleaseCheck(
            "CREDENTIAL_SECRET_KEY",
            "pass" if bool(settings.credential_secret_key) else "warning",
            "set" if settings.credential_secret_key else "not set",
            "python main.py init" if not settings.credential_secret_key else None,
        )
    )
    checks.append(ReleaseCheck("DeepSeek", "info", f"enabled={settings.llm_enabled}; model={settings.deepseek_model}; api_key={'set' if settings.deepseek_api_key else 'not set'}"))
    checks.append(ReleaseCheck("Doc fetch", "info", f"enabled={settings.doc_fetch_enabled}; allow_non_official={settings.doc_fetch_allow_non_official}"))
    flags = integration_flags()
    checks.append(ReleaseCheck("Integration flags", "info", ", ".join(f"{key}={value}" for key, value in flags.items())))
    checks.append(_executable_check("nmap", "Optional nmap binary for richer scanning."))
    for module in ("scapy", "fastapi", "uvicorn", "pytest"):
        checks.append(_module_check(module))

    return ReleaseCommandResult(
        title="Network Assistant Doctor",
        summary=_summary(checks),
        checks=checks,
        suggested_commands=["pytest", "python -m compileall app tests", "python main.py lab integration-check"],
    )


def safe_config() -> dict[str, object]:
    flags = integration_flags()
    return {
        "database_url": settings.database_url,
        "database_path": str(database_file_path()) if database_file_path() else None,
        "llm_enabled": settings.llm_enabled,
        "deepseek_base_url": settings.deepseek_base_url,
        "deepseek_model": settings.deepseek_model,
        "deepseek_api_key": "set" if settings.deepseek_api_key else "not set",
        "doc_fetch_enabled": settings.doc_fetch_enabled,
        "doc_fetch_allow_non_official": settings.doc_fetch_allow_non_official,
        "server_host": SERVER_HOST,
        "server_port": SERVER_PORT,
        "integration_flags": flags,
        "credential_secret_key": "set" if settings.credential_secret_key else "not set",
    }


def config_paths(base_dir: Path = BASE_DIR) -> dict[str, str | None]:
    return {
        "project_root": str(base_dir),
        "data_dir": str(base_dir / "data"),
        "database_path": str(database_file_path()) if database_file_path() else None,
        "docs_dir": str(base_dir / "docs"),
        "snapshots": "stored in SQLite table device_config_snapshots",
    }


def v1_readiness(base_dir: Path = BASE_DIR) -> ReleaseCommandResult:
    checks: list[ReleaseCheck] = []
    pyproject = base_dir / "pyproject.toml"
    checks.append(_path_check("Package metadata", pyproject, should_exist=True))
    checks.append(
        ReleaseCheck(
            "Version command",
            "pass" if DISPLAY_VERSION in version_text() else "fail",
            version_text().replace("\n", " / "),
        )
    )
    checks.extend(_required_doc_checks(base_dir))
    checks.append(_path_check("Tests folder", base_dir / "tests", should_exist=True))
    checks.append(_path_check("Integration tests", base_dir / "tests" / "integration", should_exist=True))
    try:
        (base_dir / "data").mkdir(parents=True, exist_ok=True)
        checks.append(ReleaseCheck("Data directory", "pass", str(base_dir / "data")))
    except Exception as exc:
        checks.append(ReleaseCheck("Data directory", "fail", str(exc), "python main.py init"))
    try:
        init_db()
        tables = set(inspect(engine).get_table_names())
        checks.append(ReleaseCheck("Agent logs table", "pass" if "agent_action_logs" in tables else "fail", "agent_action_logs"))
        checks.append(ReleaseCheck("Snapshot table", "pass" if "device_config_snapshots" in tables else "fail", "device_config_snapshots"))
    except Exception as exc:
        checks.append(ReleaseCheck("SQLite schema", "fail", str(exc), "python main.py init"))
    checks.append(_module_symbol_check("Snapshot service", "app.services.config_snapshot", "capture_pre_change_snapshot"))
    checks.append(_module_symbol_check("Topology service", "app.services.topology", "build_topology_snapshot"))
    checks.append(_module_symbol_check("Agent parser", "app.agent.intent_parser", "parse_intent"))
    checks.append(_supported_ops_doc_check(base_dir))
    status = _readiness_status(checks)
    return ReleaseCommandResult(
        title="v1 Readiness",
        summary=f"v1 Readiness: {status}",
        checks=checks,
        suggested_commands=["nat doctor", "pytest", "python -m compileall app tests", "nat lab integration-check"],
    )


def _ensure_credential_key(env_text: str) -> tuple[str, bool]:
    lines = env_text.splitlines()
    found = False
    changed = False
    key = generate_credential_key()
    output: list[str] = []
    for line in lines:
        if line.startswith("CREDENTIAL_SECRET_KEY="):
            found = True
            if line.split("=", 1)[1].strip():
                output.append(line)
            else:
                output.append(f"CREDENTIAL_SECRET_KEY={key}")
                changed = True
        else:
            output.append(line)
    if not found:
        output.append(f"CREDENTIAL_SECRET_KEY={key}")
        changed = True
    return "\n".join(output).rstrip() + "\n", changed


def _path_check(name: str, path: Path, should_exist: bool, recommendation: str | None = None) -> ReleaseCheck:
    exists = path.exists()
    return ReleaseCheck(name, "pass" if exists == should_exist else "warning", str(path), recommendation if not exists else None)


def _executable_check(name: str, description: str) -> ReleaseCheck:
    path = shutil.which(name)
    return ReleaseCheck(name, "pass" if path else "warning", path or f"Not found. {description}")


def _module_check(module: str) -> ReleaseCheck:
    found = importlib.util.find_spec(module) is not None
    return ReleaseCheck(module, "pass" if found else "warning", "available" if found else "not importable")


def _module_symbol_check(name: str, module: str, symbol: str) -> ReleaseCheck:
    try:
        imported = __import__(module, fromlist=[symbol])
        found = hasattr(imported, symbol)
    except Exception as exc:
        return ReleaseCheck(name, "fail", str(exc))
    return ReleaseCheck(name, "pass" if found else "fail", f"{module}.{symbol}")


def _required_doc_checks(base_dir: Path) -> list[ReleaseCheck]:
    return [
        ReleaseCheck(
            f"Doc: {path}",
            "pass" if (base_dir / path).exists() else "fail",
            str(base_dir / path),
        )
        for path in REQUIRED_V1_DOCS
    ]


def _supported_ops_doc_check(base_dir: Path) -> ReleaseCheck:
    path = base_dir / "docs" / "SUPPORTED_OPERATIONS.md"
    if not path.exists():
        return ReleaseCheck("Unsupported operations documented", "fail", str(path))
    text = path.read_text(encoding="utf-8").lower()
    required = ("arbitrary ssh", "firewall execution", "nat execution", "llm-generated command execution")
    missing = [item for item in required if item not in text]
    return ReleaseCheck(
        "Unsupported dangerous operations documented",
        "pass" if not missing else "fail",
        "Documented." if not missing else f"Missing: {', '.join(missing)}",
    )


def _readiness_status(checks: list[ReleaseCheck]) -> str:
    if any(check.status == "fail" for check in checks):
        return "FAIL"
    if any(check.status == "warning" for check in checks):
        return "WARN"
    return "PASS"


def _summary(checks: list[ReleaseCheck]) -> str:
    failed = sum(1 for check in checks if check.status == "fail")
    warnings = sum(1 for check in checks if check.status == "warning")
    passed = sum(1 for check in checks if check.status == "pass")
    return f"Release readiness: pass={passed}, warning={warnings}, fail={failed}."
