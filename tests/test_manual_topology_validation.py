import pytest

from app.services.manual_topology import (
    ManualTopologyError,
    delete_manual_node,
    validate_label,
    validate_node_key,
    validate_node_type,
    validate_notes,
    validate_optional_ip,
)


def test_manual_node_key_validation_allows_safe_keys():
    validate_node_key("core-switch_1.lab")


def test_manual_node_key_validation_rejects_unsafe_key():
    with pytest.raises(ManualTopologyError):
        validate_node_key("core switch;reload")


def test_manual_node_type_validation_rejects_unknown_type():
    with pytest.raises(ManualTopologyError):
        validate_node_type("firewallish")


def test_manual_label_and_notes_length_validation():
    with pytest.raises(ManualTopologyError):
        validate_label("x" * 81)
    with pytest.raises(ManualTopologyError):
        validate_notes("x" * 1001)


def test_manual_ip_validation_rejects_invalid_ip():
    with pytest.raises(ManualTopologyError):
        validate_optional_ip("999.999.999.999")


def test_delete_requires_confirmation_guard():
    with pytest.raises(ManualTopologyError):
        delete_manual_node(1, confirm=False)
