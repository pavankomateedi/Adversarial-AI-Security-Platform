"""Pydantic Settings for AgentForge — loaded from environment / .env file."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings.

    All env vars from CLAUDE.md Section 3 are defined here. Anything secret is
    typed as `SecretStr` so it cannot accidentally leak through `repr()` or
    structured logs.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Target system ---
    backend_url: str = Field(default="http://localhost:3000", description="Clinical Co-Pilot URL")
    backend_api_key: SecretStr | None = None
    # The Co-Pilot uses session-cookie auth via POST /auth/login.
    backend_username: str | None = None
    backend_password: SecretStr | None = None
    # Comma-separated list of patient_ids the test user is RBAC-assigned to.
    backend_test_patient_ids: str = ""

    # --- LLM providers ---
    openai_api_key: SecretStr | None = None
    anthropic_api_key: SecretStr | None = None
    groq_api_key: SecretStr | None = None
    mistral_api_key: SecretStr | None = None

    # --- Database ---
    database_url: str = Field(
        default="postgresql+asyncpg://agentforge:agentforge@localhost:5432/agentforge",
    )
    redis_url: str = Field(default="redis://localhost:6379/0")

    # --- Security ---
    secret_key: SecretStr = Field(default=SecretStr("dev-only-not-for-production"))
    jwt_algorithm: str = "HS256"
    jwt_expiry_minutes: int = 60
    admin_api_key: SecretStr = Field(default=SecretStr("dev-admin-key"))

    # --- Observability ---
    langfuse_public_key: SecretStr | None = None
    langfuse_secret_key: SecretStr | None = None
    langfuse_host: str = "https://cloud.langfuse.com"
    prometheus_port: int = 9090

    # --- Platform ---
    environment: Literal["development", "staging", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    max_concurrent_campaigns: int = 3
    max_tokens_per_campaign: int = 500_000
    cost_alert_threshold_usd: float = 10.00

    # --- Rate limiting ---
    rate_limit_requests_per_minute: int = 60
    rate_limit_burst: int = 10

    # --- CORS ---
    cors_allowed_origins: str = "http://localhost:3000,http://localhost:8000"

    @field_validator("secret_key")
    @classmethod
    def _secret_key_strength(cls, v: SecretStr) -> SecretStr:
        # Reject the literal placeholder, but allow the dev default during local boot.
        if v.get_secret_value() == "change-me-to-a-64-char-random-hex-string-do-not-use-in-production":
            raise ValueError("SECRET_KEY must be set to a real value (openssl rand -hex 32).")
        return v

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_allowed_origins.split(",") if o.strip()]

    @property
    def test_patient_ids_list(self) -> list[str]:
        return [p.strip() for p in self.backend_test_patient_ids.split(",") if p.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached settings instance.

    Why: settings construction reads `.env` and runs validators; caching avoids
    repeating that on every request while still letting tests override via
    `get_settings.cache_clear()`.
    """
    return Settings()
