import pytest

from app.command_policy import validate_readonly_command
from app.services.config_executor import ConfigExecutionError, validate_cisco_interface_execution_commands


def test_description_command_template_passes():
    validate_cisco_interface_execution_commands(
        "cisco_interface_description",
        ["interface Gi0/5", " description LAB-PC-01"],
        ["interface Gi0/5", " no description"],
    )


def test_access_port_command_template_passes():
    validate_cisco_interface_execution_commands(
        "cisco_access_port",
        [
            "interface Gi0/5",
            " switchport mode access",
            " switchport access vlan 30",
            " spanning-tree portfast",
            " description LAB-PC-01",
        ],
        ["interface Gi0/5", " no switchport access vlan 30", " no spanning-tree portfast", " no description"],
    )


def test_unsafe_trunk_command_is_blocked():
    with pytest.raises(ConfigExecutionError):
        validate_cisco_interface_execution_commands(
            "cisco_access_port",
            ["interface Gi0/5", "switchport mode trunk", "switchport access vlan 30"],
            ["interface Gi0/5", "no switchport access vlan 30"],
        )


def test_interface_range_is_blocked():
    with pytest.raises(ConfigExecutionError):
        validate_cisco_interface_execution_commands(
            "cisco_access_port",
            ["interface range Gi0/5-Gi0/10", "switchport mode access", "switchport access vlan 30"],
            ["interface range Gi0/5-Gi0/10", "no switchport access vlan 30"],
        )


def test_unsafe_description_is_blocked():
    with pytest.raises(ConfigExecutionError):
        validate_cisco_interface_execution_commands(
            "cisco_interface_description",
            ["interface Gi0/5", "description LAB;reload"],
            ["interface Gi0/5", "no description"],
        )


def test_rollback_validator_accepts_only_safe_rollback():
    with pytest.raises(ConfigExecutionError):
        validate_cisco_interface_execution_commands(
            "cisco_access_port",
            ["interface Gi0/5", "switchport mode access", "switchport access vlan 30"],
            ["interface Gi0/5", "shutdown"],
        )


def test_show_running_config_interface_is_readonly_allowed():
    validate_readonly_command("cisco_ios", "show running-config interface Gi0/5")
