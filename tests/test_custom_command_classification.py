import pytest

from app.services.custom_command_validator import (
    classify_custom_command,
    validate_precheck_command,
    validate_verification_command,
)


def test_route_nat_mangle_commands_classify_without_blanket_blocking():
    route = classify_custom_command("/ip route add gateway=192.168.88.1 comment=\"NA-PLAN-1\"", "mikrotik_routeros")
    nat = classify_custom_command("/ip firewall nat add chain=srcnat action=masquerade comment=\"NA-PLAN-1\"", "mikrotik_routeros")
    mangle = classify_custom_command("/ip firewall mangle add chain=prerouting action=mark-routing comment=\"NA-PLAN-1\"", "mikrotik_routeros")

    assert route.category == "requires_double_confirmation"
    assert nat.category == "requires_double_confirmation"
    assert mangle.category == "requires_double_confirmation"


@pytest.mark.parametrize("command", ["/tool fetch url=http://evil", "/system reset-configuration", "/user add name=x", "username admin password pass", "enable secret test"])
def test_security_abuse_commands_are_blocked(command):
    platform = "mikrotik_routeros" if command.startswith("/") else "cisco_ios"

    result = classify_custom_command(command, platform)

    assert result.category == "blocked_security_abuse"


@pytest.mark.parametrize("command", ["ip route 10.0.0.0 255.255.255.0 192.168.88.1 && reload", "/ip route print; /system reboot"])
def test_shell_operators_are_blocked(command):
    result = classify_custom_command(command, "cisco_ios")

    assert result.category == "blocked_security_abuse"


def test_precheck_and_verification_must_be_readonly():
    validate_precheck_command("/ip firewall nat print", "mikrotik_routeros")
    validate_precheck_command("show ip route", "cisco_ios")
    validate_verification_command("/ping 8.8.8.8 count=3", "mikrotik_routeros")
    validate_verification_command("show running-config | include ip route", "cisco_ios")

    with pytest.raises(ValueError):
        validate_precheck_command("/ip route add gateway=192.168.88.1", "mikrotik_routeros")
    with pytest.raises(ValueError):
        validate_verification_command("configure terminal", "cisco_ios")
