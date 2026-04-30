import pytest

from app.safety import UnsafeNetworkError
from app.services.nmap_tool import validate_nmap_profile, validate_nmap_target


def test_public_ip_target_is_blocked():
    with pytest.raises(UnsafeNetworkError):
        validate_nmap_target("8.8.8.8")


def test_large_cidr_is_blocked():
    with pytest.raises(UnsafeNetworkError):
        validate_nmap_target("192.168.0.0/16")


def test_unsupported_profile_is_blocked():
    with pytest.raises(UnsafeNetworkError):
        validate_nmap_profile("aggressive")


def test_raw_flags_are_not_accepted_as_target():
    with pytest.raises(UnsafeNetworkError):
        validate_nmap_target("-A 192.168.88.1")


def test_hostname_targets_are_blocked():
    with pytest.raises(UnsafeNetworkError):
        validate_nmap_target("router.local")


def test_private_ip_and_24_are_allowed():
    assert validate_nmap_target("192.168.88.1") == "192.168.88.1"
    assert validate_nmap_target("192.168.88.0/24") == "192.168.88.0/24"
