from typer.testing import CliRunner
from fastapi import HTTPException

import main
from app import server


runner = CliRunner()


def test_tools_cli_commands_work():
    assert runner.invoke(main.app, ["tools", "list"]).exit_code == 0
    assert runner.invoke(main.app, ["tools", "search", "router"]).exit_code == 0
    assert runner.invoke(main.app, ["tools", "show", "connect_collect_readonly"]).exit_code == 0


def test_skills_cli_commands_work():
    assert runner.invoke(main.app, ["skills", "list"]).exit_code == 0
    assert runner.invoke(main.app, ["skills", "search", "router"]).exit_code == 0
    assert runner.invoke(main.app, ["skills", "show", "router_connection"]).exit_code == 0


def test_tools_server_endpoints_work():
    assert server.tools_endpoint()["tools"]
    assert server.tools_search_endpoint("router")["tools"][0]["tool_name"] == "router_connect_workflow"
    assert server.tool_show_endpoint("connect_collect_readonly")["tool"]["tool_name"] == "connect_collect_readonly"


def test_skills_server_endpoints_work():
    assert server.skills_endpoint()["skills"]
    assert server.skills_search_endpoint("router")["skills"]
    assert server.skill_show_endpoint("router_connection")["skill"]["metadata"]["skill_name"] == "router_connection"


def test_server_endpoint_404s():
    try:
        server.tool_show_endpoint("missing")
    except HTTPException as exc:
        assert exc.status_code == 404
    else:
        raise AssertionError("expected HTTPException")
