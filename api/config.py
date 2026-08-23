"""Application configuration.

This module defines configuration parameters used throughout the API,
worker and detection engine.  Values are loaded from environment
variables with sensible defaults for development.  At runtime you
should supply a `.env` file or real environment variables (see
`deploy/env.example`).
"""

from __future__ import annotations

import os
from datetime import timedelta

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application configuration settings.

    METRICS_SAMPLE_ROWS: The maximum number of rows to accumulate in memory for computing
    anonymisation metrics on large datasets (default 200000).
    """

    model_config = SettingsConfigDict(
        env_file=os.getenv("ENV_FILE", ".env"), env_file_encoding="utf-8", case_sensitive=False
    )

    database_url: str = Field(...)
    redis_url: str = Field(...)

    jwt_secret_key: str = Field(...)
    jwt_algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=60 * 8)

    encryption_key: str = Field(...)

    data_retention_hours: int = Field(default=24)
    allow_egress: bool = Field(default=False)

    tls_cert_file: str | None = Field(default=None)
    tls_key_file: str | None = Field(default=None)

    max_file_size_mb: int = Field(default=2048)
    max_chunk_size: int = Field(default=10000)

    rate_limit_per_minute: int = Field(default=100)

    log_level: str = Field(default="INFO")
    log_format: str = Field(default="json")
    log_dir: str = Field(default="logs")

    enable_security_headers: bool = Field(default=True)

    cors_origins: str = Field(default="http://localhost:3000,https://localhost:3000")  # noqa: E501

    default_admin_user: str = Field(default="admin@piiscope.local")
    default_admin_password: str = Field(default="adminpass")

    postgres_user: str = Field(default="piiscope")
    postgres_password: str = Field(default="piiscope")
    postgres_db: str = Field(default="piiscope")

    metrics_sample_rows: int = Field(default=200000)

    @field_validator("jwt_secret_key")
    @classmethod
    def validate_jwt_secret(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("JWT secret key must be at least 32 characters long")
        return v

    @field_validator("max_file_size_mb")
    @classmethod
    def validate_file_size(cls, v: int) -> int:
        if v <= 0 or v > 10240:
            raise ValueError("File size must be between 1MB and 10240MB")
        return v

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of: {', '.join(valid_levels)}")
        return v.upper()

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",")]

    @property
    def access_token_expires(self) -> timedelta:
        return timedelta(minutes=self.access_token_expire_minutes)


settings = Settings()  # Singleton settings object
