from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.services import lab_integration
from app.models import Base
from app.services.lab_integration import (
    integration_check,
    integration_flags,
    integration_report,
    real_config_enabled,
    real_dhcp_enabled,
    redact_integration_env,
)


def test_integration_tests_disabled_by_default():
    flags = integration_flags({})

    assert flags["run_integration_tests"] is False
    assert flags["allow_real_config_tests"] is False


def test_real_config_tests_disabled_by_default():
    assert real_config_enabled({}) is False


def test_dhcp_real_tests_require_separate_flag():
    assert real_dhcp_enabled({"ALLOW_REAL_CONFIG_TESTS": "true"}) is False
    assert real_dhcp_enabled({"ALLOW_REAL_CONFIG_TESTS": "true", "ALLOW_REAL_DHCP_TESTS": "true"}) is True


def test_integration_check_redacts_passwords():
    env = {
        "RUN_INTEGRATION_TESTS": "true",
        "LAB_CISCO_PASSWORD": "secret",
        "LAB_MIKROTIK_PASSWORD": "secret2",
    }
    result = integration_check(env=env)
    rendered = "\n".join(check.detail for check in result.checks)

    assert "secret" not in rendered
    assert "***REDACTED***" in rendered
    assert redact_integration_env(env)["LAB_CISCO_PASSWORD"] == "***REDACTED***"


def test_integration_check_reports_missing_env_vars():
    result = integration_check(env={})
    details = "\n".join(check.detail for check in result.checks)

    assert "LAB_CISCO_IP" in details
    assert "LAB_MIKROTIK_IP" in details


def test_connect_not_used_by_default(monkeypatch):
    called = False

    def fake_test_connection(_ip):
        nonlocal called
        called = True

    monkeypatch.setattr(lab_integration, "test_connection", fake_test_connection)

    result = integration_check(connect=False, env={})

    assert called is False
    assert any("--connect" in check.detail and "was not used" in check.detail for check in result.checks)


def test_integration_report_runs_without_network(monkeypatch):
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    monkeypatch.setattr(lab_integration, "init_db", lambda: None)
    monkeypatch.setattr(lab_integration, "get_session", session_local)

    result = integration_report(env={})

    assert result.title == "Lab Integration Report"
    assert result.checks
