from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env."""

    database_url: str = Field(default=f"sqlite:///{BASE_DIR / 'data' / 'network_assistant.db'}")
    port_scan_timeout_seconds: float = Field(default=0.5, ge=0.1, le=5.0)
    discovery_timeout_seconds: float = Field(default=2.0, ge=0.5, le=10.0)
    llm_enabled: bool = False
    deepseek_api_key: str = ""
    deepseek_base_url: str = "https://api.deepseek.com"
    deepseek_model: str = "deepseek-chat"
    credential_secret_key: str = ""
    doc_fetch_enabled: bool = False
    doc_fetch_allow_non_official: bool = False
    doc_fetch_timeout_seconds: float = Field(default=15.0, ge=1.0, le=60.0)

    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
