import pytest

from app.command_policy import CommandPolicyError, collection_commands_for, validate_readonly_command


def test_cisco_readonly_command_is_allowed():
    validate_readonly_command("cisco_ios", "show vlan brief")


def test_cisco_unsafe_command_is_rejected():
    with pytest.raises(CommandPolicyError):
        validate_readonly_command("cisco_ios", "configure terminal")


def test_mikrotik_readonly_command_is_allowed():
    validate_readonly_command("mikrotik_routeros", "/interface print")


def test_mikrotik_dhcp_readonly_commands_are_allowed_and_collected():
    for command in ("/ip pool print", "/ip dhcp-server print", "/ip dhcp-server network print"):
        validate_readonly_command("mikrotik_routeros", command)
        assert command in collection_commands_for("mikrotik_routeros")


def test_mikrotik_config_command_is_rejected():
    with pytest.raises(CommandPolicyError):
        validate_readonly_command("mikrotik_routeros", "/ip address add address=192.168.50.1/24 interface=bridge")
