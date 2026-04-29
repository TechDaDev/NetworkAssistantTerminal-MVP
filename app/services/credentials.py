from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.database import get_session, init_db
from app.models import Device, DeviceCredential
from app.services.security import encrypt_secret


SUPPORTED_PLATFORM_HINTS = {"cisco_ios", "mikrotik_routeros", "linux", "unknown_ssh"}


class CredentialError(RuntimeError):
    """Raised when credentials cannot be created or found."""


def save_device_credential(
    ip_address: str,
    username: str,
    password: str,
    platform_hint: str,
    port: int = 22,
) -> DeviceCredential:
    if platform_hint not in SUPPORTED_PLATFORM_HINTS:
        raise CredentialError(f"Unsupported platform hint `{platform_hint}`.")
    if port <= 0 or port > 65535:
        raise CredentialError("Port must be between 1 and 65535.")

    init_db()
    now = datetime.now(timezone.utc)
    with get_session() as session:
        device = session.scalar(select(Device).where(Device.ip_address == ip_address))
        if device is None:
            raise CredentialError("Device not found in local inventory. Run a scan first.")

        credential = session.scalar(
            select(DeviceCredential).where(
                DeviceCredential.device_id == device.id,
                DeviceCredential.connection_type == "ssh",
            )
        )
        if credential is None:
            credential = DeviceCredential(device=device, connection_type="ssh", created_at=now)
            session.add(credential)

        credential.username = username
        credential.encrypted_password = encrypt_secret(password)
        credential.port = port
        credential.platform_hint = platform_hint
        credential.status = "untested"
        credential.updated_at = now
        session.commit()
        session.refresh(credential)
        return credential


def list_device_credentials() -> list[DeviceCredential]:
    init_db()
    with get_session() as session:
        return list(
            session.scalars(
                select(DeviceCredential)
                .options(selectinload(DeviceCredential.device))
                .order_by(DeviceCredential.updated_at.desc())
            ).all()
        )


def get_credential_for_ip(ip_address: str) -> DeviceCredential | None:
    init_db()
    with get_session() as session:
        return session.scalar(
            select(DeviceCredential)
            .join(Device)
            .options(selectinload(DeviceCredential.device))
            .where(Device.ip_address == ip_address, DeviceCredential.connection_type == "ssh")
        )


def delete_device_credential(ip_address: str) -> bool:
    init_db()
    with get_session() as session:
        credential = session.scalar(
            select(DeviceCredential).join(Device).where(Device.ip_address == ip_address)
        )
        if credential is None:
            return False
        session.delete(credential)
        session.commit()
        return True
