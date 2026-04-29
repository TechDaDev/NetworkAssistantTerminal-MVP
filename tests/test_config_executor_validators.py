import pytest

from app.services.config_executor import (
    ConfigExecutionError,
    validate_cisco_vlan_execution_commands,
    validate_execution_confirmation,
    validate_mikrotik_address_execution_commands,
)


def test_cisco_vlan_command_template_passes():
    validate_cisco_vlan_execution_commands(
        [
            "vlan 30",
            "name LAB",
            "interface range Gi0/5-Gi0/10",
            "switchport mode access",
            "switchport access vlan 30",
            "spanning-tree portfast",
        ],
        [
            "interface range Gi0/5-Gi0/10",
            "no switchport access vlan 30",
            "no spanning-tree portfast",
            "no vlan 30",
        ],
    )


def test_cisco_trunk_change_is_rejected():
    with pytest.raises(ConfigExecutionError):
        validate_cisco_vlan_execution_commands(
            ["vlan 30", "interface range Gi0/5", "switchport mode trunk"],
            ["no vlan 30"],
        )


def test_mikrotik_address_command_template_passes():
    validate_mikrotik_address_execution_commands(
        ['/ip address add address=192.168.50.1/24 interface=bridge comment="LAB gateway"'],
        ['/ip address remove [find address="192.168.50.1/24" interface="bridge"]'],
    )


def test_mikrotik_rollback_must_match_proposed():
    with pytest.raises(ConfigExecutionError):
        validate_mikrotik_address_execution_commands(
            ["/ip address add address=192.168.50.1/24 interface=bridge"],
            ['/ip address remove [find address="192.168.51.1/24" interface="bridge"]'],
        )


def test_mikrotik_unsafe_command_is_rejected():
    with pytest.raises(ConfigExecutionError):
        validate_mikrotik_address_execution_commands(
            ["/system reboot"],
            ['/ip address remove [find address="192.168.50.1/24" interface="bridge"]'],
        )


def test_wrong_execution_confirmation_fails():
    with pytest.raises(ConfigExecutionError):
        validate_execution_confirmation("EXECUTE", 5, "EXECUTE 5")


def test_exact_execution_confirmation_passes():
    validate_execution_confirmation("EXECUTE", 5, "EXECUTE PLAN 5")
