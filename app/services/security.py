from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from app.config import settings


class CredentialSecurityError(RuntimeError):
    """Raised when credential encryption is unavailable or invalid."""


def generate_credential_key() -> str:
    return Fernet.generate_key().decode("ascii")


def _fernet() -> Fernet:
    if not settings.credential_secret_key:
        raise CredentialSecurityError(
            "CREDENTIAL_SECRET_KEY is not set. Run `python main.py security generate-key` "
            "and add the value to `.env`."
        )
    try:
        return Fernet(settings.credential_secret_key.encode("ascii"))
    except ValueError as exc:
        raise CredentialSecurityError("CREDENTIAL_SECRET_KEY is not a valid Fernet key.") from exc


def encrypt_secret(value: str) -> str:
    return _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_secret(value: str) -> str:
    try:
        return _fernet().decrypt(value.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise CredentialSecurityError("Stored credential could not be decrypted with the current key.") from exc
