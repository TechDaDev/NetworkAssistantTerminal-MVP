import ipaddress


class UnsafeNetworkError(ValueError):
    """Raised when a requested scan target violates Phase 1 safety rules."""


PRIVATE_RANGES = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def is_private_cidr(cidr: str) -> bool:
    network = ipaddress.ip_network(cidr, strict=False)
    return any(network.subnet_of(private_range) for private_range in PRIVATE_RANGES)


def is_scan_size_allowed(cidr: str) -> bool:
    network = ipaddress.ip_network(cidr, strict=False)
    return network.prefixlen >= 24


def validate_scan_target(cidr: str) -> None:
    network = ipaddress.ip_network(cidr, strict=False)
    if not is_private_cidr(str(network)):
        raise UnsafeNetworkError(
            f"Refusing to scan {network}. Phase 1 only allows local private networks "
            "(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)."
        )
    if not is_scan_size_allowed(str(network)):
        raise UnsafeNetworkError(
            f"Refusing to scan {network}. Phase 1 blocks networks larger than /24."
        )
