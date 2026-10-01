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
    cors_origins: list[str] = ["http://localhost:5173"]

    # Password reset delivery over SMTP. Reset requests answer 503 until host, sender and
    # frontend URL are configured; port 465 uses implicit TLS, any other port requires STARTTLS.
    email_host: str | None = None
    email_port: int = Field(default=587, gt=0, le=65535)
    email_username: str | None = None
    email_password: SecretStr | None = None
    email_from: str | None = None
    frontend_base_url: str | None = None
    password_reset_token_expire_minutes: int = Field(default=30, gt=0, le=1440)


@lru_cache
def get_settings() -> Settings:
    return Settings()
