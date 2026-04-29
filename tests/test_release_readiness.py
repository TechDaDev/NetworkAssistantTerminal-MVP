from typer.testing import CliRunner

import main
from app.release import v1_readiness


runner = CliRunner()


def test_release_readiness_service_runs_without_network():
    result = v1_readiness()

    assert result.title == "v1 Readiness"
    assert result.summary.startswith("v1 Readiness:")
    assert any(check.name == "Snapshot service" for check in result.checks)
    assert any(check.name == "Topology service" for check in result.checks)


def test_release_readiness_cli_runs():
    result = runner.invoke(main.app, ["release", "readiness"])

    assert result.exit_code == 0
    assert "v1 Readiness:" in result.output
