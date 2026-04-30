from pathlib import Path
import tomllib

from typer.testing import CliRunner

import main


runner = CliRunner()


def test_version_command_works():
    result = runner.invoke(main.app, ["version"])

    assert result.exit_code == 0
    assert "Network Assistant" in result.output
    assert "Version: 1.0.0-rc3" in result.output


def test_pyproject_contains_console_scripts():
    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))

    assert data["project"]["name"] == "network-assistant"
    assert data["project"]["scripts"]["network-assistant"] == "main:app"
    assert data["project"]["scripts"]["nat"] == "main:app"


def test_importing_main_app_still_works():
    assert main.app is not None
