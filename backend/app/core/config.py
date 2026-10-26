from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "NETRA API"
    app_description: str = "Cyber Decision Intelligence Platform"
    app_version: str = "1.0.0"
    environment: str = "development"

    # SecretStr keeps the credentials masked in repr/logs.
    database_url: SecretStr
    jwt_secret_key: SecretStr = Field(min_length=32)
    jwt_algorithm: Literal["HS256"] = "HS256"
    access_token_expire_minutes: int = Field(default=60, gt=0)
    # The Vite dev server is reached as localhost or 127.0.0.1; browsers treat them as different origins.
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    # Self-service sign-up through POST /api/auth/register. Off unless a deployment opts in; otherwise
    # an administrator creates accounts with backend/scripts/netra_users.py.
    allow_public_registration: bool = False

    # Password reset delivery over SMTP. Reset requests answer 503 until host, sender and
    # frontend URL are configured; port 465 uses implicit TLS, any other port requires STARTTLS.
    email_host: str | None = None
    email_port: int = Field(default=587, gt=0, le=65535)
    email_username: str | None = None
    email_password: SecretStr | None = None
    email_from: str | None = None
    frontend_base_url: str | None = None
    password_reset_token_expire_minutes: int = Field(default=30, gt=0, le=1440)

    # Dataset CSV uploads (validation only). The API enforces both caps; any reverse proxy in front
    # of it has its own request-size limit, which must be at least this size (docs/DATASET_IMPORTS.md).
    import_max_upload_bytes: int = Field(default=25 * 1024 * 1024, gt=0, le=1024 * 1024 * 1024)
    import_max_rows: int = Field(default=100_000, gt=0, le=10_000_000)

    # ThreatFox (abuse.ch) Auth-Key, used only by scripts/netra_threatfox_sync.py as a request header.
    # Backend-only: never sent to the frontend, stored in the database or logged.
    threatfox_auth_key: SecretStr | None = None
    # ThreatFox indicators stop matching once their latest ThreatFox date is older than this (never deleted).
    threatfox_expiry_days: int = Field(default=90, ge=1, le=180)


@lru_cache
def get_settings() -> Settings:
    return Settings()
