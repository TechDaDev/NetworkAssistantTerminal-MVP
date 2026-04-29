import pytest

from app.services.config_planner import ConfigPlanError, validate_mikrotik_dhcp_planning_commands


VALID_PROPOSED = [
    "/ip pool add name=lab-pool ranges=192.168.50.100-192.168.50.200",
    '/ip dhcp-server add name=lab-dhcp interface=bridge address-pool=lab-pool disabled=no comment="LAB DHCP"',
    "/ip dhcp-server network add address=192.168.50.0/24 gateway=192.168.50.1 dns-server=8.8.8.8,1.1.1.1",
]
VALID_ROLLBACK = [
    '/ip dhcp-server remove [find name="lab-dhcp"]',
    '/ip dhcp-server network remove [find address="192.168.50.0/24"]',
    '/ip pool remove [find name="lab-pool"]',
]


def test_mikrotik_dhcp_validator_accepts_generated_templates():
    validate_mikrotik_dhcp_planning_commands(VALID_PROPOSED, VALID_ROLLBACK)


def test_mikrotik_dhcp_validator_rejects_rollback_mismatch():
    rollback = list(VALID_ROLLBACK)
    rollback[2] = '/ip pool remove [find name="wrong-pool"]'

    with pytest.raises(ConfigPlanError):
        validate_mikrotik_dhcp_planning_commands(VALID_PROPOSED, rollback)


@pytest.mark.parametrize(
    "command",
    [
        "/system reboot",
        "/tool fetch url=http://example.com",
        "/ip pool add name=lab-pool ranges=192.168.50.100-192.168.50.200; /system reboot",
        "/ip dhcp-server add name=lab-dhcp interface=bridge address-pool=lab-pool disabled=no password=test",
    ],
)
def test_mikrotik_dhcp_validator_rejects_unsafe_commands(command):
    proposed = list(VALID_PROPOSED)
    proposed[0] = command

    with pytest.raises(ConfigPlanError):
        validate_mikrotik_dhcp_planning_commands(proposed, VALID_ROLLBACK)


def test_mikrotik_dhcp_validator_rejects_public_network():
    proposed = list(VALID_PROPOSED)
    proposed[2] = "/ip dhcp-server network add address=8.8.8.0/24 gateway=8.8.8.1"
    rollback = list(VALID_ROLLBACK)
    rollback[1] = '/ip dhcp-server network remove [find address="8.8.8.0/24"]'

    with pytest.raises(ConfigPlanError):
        validate_mikrotik_dhcp_planning_commands(proposed, rollback)
