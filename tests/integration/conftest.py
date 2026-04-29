from __future__ import annotations

import os

import pytest


def _enabled(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def pytest_collection_modifyitems(config, items):
    if _enabled("RUN_INTEGRATION_TESTS"):
        return
    skip_integration = pytest.mark.skip(reason="RUN_INTEGRATION_TESTS=true is required for real lab integration tests.")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)


@pytest.fixture
def allow_real_config_tests() -> bool:
    return _enabled("ALLOW_REAL_CONFIG_TESTS")


@pytest.fixture
def allow_real_dhcp_tests() -> bool:
    return _enabled("ALLOW_REAL_CONFIG_TESTS") and _enabled("ALLOW_REAL_DHCP_TESTS")
