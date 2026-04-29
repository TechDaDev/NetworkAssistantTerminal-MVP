from app.schemas import DeviceFingerprint, HostDiscoveryResult, PortScanResult


def fingerprint_device(
    host: HostDiscoveryResult,
    ports: list[PortScanResult],
    gateway_ip: str | None = None,
) -> DeviceFingerprint:
    open_ports = {port.port for port in ports}
    notes: list[str] = []
    vendor_guess = "Unknown"
    type_guess = "Unknown"
    confidence = "Low"

    if open_ports.intersection({8291, 8728, 8729}):
        vendor_guess = "MikroTik"
        type_guess = "Router"
        confidence = "High"

    if gateway_ip and host.ip_address == gateway_ip:
        type_guess = "Router/Gateway"
        confidence = "High"

    if open_ports.intersection({80, 443, 8080, 8443}):
        notes.append("Web management or web service detected")
        if type_guess == "Unknown":
            type_guess = "Network or Web Device"
            confidence = "Medium"

    if 22 in open_ports:
        notes.append("SSH available")
        if confidence == "Low":
            confidence = "Medium"

    if open_ports.intersection({445, 139, 3389}):
        type_guess = "Windows Host or Server"
        if vendor_guess == "Unknown":
            vendor_guess = "Unknown"
        confidence = "Medium"

    return DeviceFingerprint(
        vendor_guess=vendor_guess,
        type_guess=type_guess,
        confidence=confidence,
        notes=notes,
    )
