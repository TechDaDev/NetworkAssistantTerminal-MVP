import pytest

from app.safety import UnsafeNetworkError, validate_scan_target


def test_public_cidr_is_blocked():
    with pytest.raises(UnsafeNetworkError):
        validate_scan_target("8.8.8.0/24")


def test_large_private_cidr_is_blocked():
    with pytest.raises(UnsafeNetworkError):
        validate_scan_target("192.168.0.0/16")


def test_private_24_is_allowed():
    validate_scan_target("192.168.88.0/24")
