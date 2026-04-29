from pathlib import Path

from typer.testing import CliRunner

import main
from app.release import config_paths, doctor, init_project, safe_config


runner = CliRunner()


def test_init_creates_data_directory_and_env(tmp_path):
    (tmp_path / ".env.example").write_text("CREDENTIAL_SECRET_KEY=\nDATABASE_URL=sqlite:///data/test.db\n", encoding="utf-8")

    result = init_project(base_dir=tmp_path)

    assert (tmp_path / "data").is_dir()
    assert (tmp_path / ".env").exists()
    assert "CREDENTIAL_SECRET_KEY=" in (tmp_path / ".env").read_text(encoding="utf-8")
    assert any(check.name == "SQLite schema" for check in result.checks)


def test_init_does_not_overwrite_env_unless_forced(tmp_path):
    (tmp_path / ".env.example").write_text("CREDENTIAL_SECRET_KEY=\nNEW_VALUE=yes\n", encoding="utf-8")
    (tmp_path / ".env").write_text("CREDENTIAL_SECRET_KEY=existing\nKEEP=yes\n", encoding="utf-8")

    init_project(base_dir=tmp_path, force=False)
    assert "KEEP=yes" in (tmp_path / ".env").read_text(encoding="utf-8")

    init_project(base_dir=tmp_path, force=True)
    env_text = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "NEW_VALUE=yes" in env_text
    assert "KEEP=yes" not in env_text


def test_doctor_runs_without_network():
    result = doctor()

    assert result.title == "Network Assistant Doctor"
    assert result.checks


def test_config_show_redacts_secrets():
    data = safe_config()

    assert data["deepseek_api_key"] in {"set", "not set"}
    assert data["credential_secret_key"] in {"set", "not set"}
    assert not any(str(value).startswith("sk-") for value in data.values())


def test_config_paths_works(tmp_path):
    paths = config_paths(base_dir=tmp_path)

    assert paths["project_root"] == str(tmp_path)
    assert paths["data_dir"] == str(tmp_path / "data")


def test_config_cli_commands_work():
    show = runner.invoke(main.app, ["config", "show"])
    paths = runner.invoke(main.app, ["config", "paths"])

    assert show.exit_code == 0
    assert "deepseek_api_key" in show.output
    assert "credential_secret_key" in show.output
    assert paths.exit_code == 0
    assert "project_root" in paths.output
