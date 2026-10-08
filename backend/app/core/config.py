"""
S.H.A.D.E. — Application Configuration
Role: Member 1 — Core Architecture + Backend + Database + Integration

Reads configuration from environment variables / .env file.
All secrets must be provided via environment; never hard-coded.
"""

from functools import lru_cache
from typing import List, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Central configuration for the S.H.A.D.E. backend.
    Source of truth: environment variables → .env file → defaults.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ───────────────────────────────────────────────────────────
    shade_env: str = Field(default="development", alias="SHADE_ENV")
    shade_host: str = Field(default="127.0.0.1", alias="SHADE_HOST")
    shade_port: int = Field(default=8000, alias="SHADE_PORT")
    debug: bool = Field(default=False, alias="DEBUG")

    @property
    def cors_origins(self) -> List[str]:
        """Only allow localhost origins — device-local enforcement."""
        return [
            f"http://localhost:{self.shade_port}",
            f"http://127.0.0.1:{self.shade_port}",
            "http://localhost:3000",   # Vite/React frontend default
            "http://127.0.0.1:3000",
        ]

    # ── Database — Local Encrypted SQLite ────────────────────────────────────
    database_url: str = Field(
        default="sqlite+aiosqlite:///./data/shade_vault.db",
        alias="DATABASE_URL",
    )
    database_encryption_provider: str = Field(
        default="sqlcipher",
        alias="DATABASE_ENCRYPTION_PROVIDER",
    )

    # ── Cryptographic Key Storage ─────────────────────────────────────────────
    key_storage_backend: str = Field(default="auto", alias="KEY_STORAGE_BACKEND")
    # Master key: loaded from OS keystore at runtime; env var only for dev fallback.
    shade_master_encryption_key: Optional[str] = Field(
        default=None, alias="SHADE_MASTER_ENCRYPTION_KEY"
    )

    # ── JWT Session Tokens ─────────────────────────────────────────────────────
    shade_jwt_secret: Optional[str] = Field(default=None, alias="SHADE_JWT_SECRET")
    shade_jwt_algorithm: str = Field(default="HS256", alias="SHADE_JWT_ALGORITHM")
    shade_access_token_expire_minutes: int = Field(
        default=15, alias="SHADE_ACCESS_TOKEN_EXPIRE_MINUTES"
    )
    shade_refresh_token_expire_days: int = Field(
        default=7, alias="SHADE_REFRESH_TOKEN_EXPIRE_DAYS"
    )

    # ── Rate Limiting ──────────────────────────────────────────────────────────
    redis_url: Optional[str] = Field(default=None, alias="REDIS_URL")
    rate_limit_per_minute: int = Field(default=60, alias="RATE_LIMIT_PER_MINUTE")

    # ── External APIs — Optional, offline-resilient ───────────────────────────
    gemini_api_key: Optional[str] = Field(default=None, alias="GEMINI_API_KEY")
    hibp_api_key: Optional[str] = Field(default=None, alias="HIBP_API_KEY")
    picovoice_access_key: Optional[str] = Field(
        default=None, alias="PICOVOICE_ACCESS_KEY"
    )

    # ── Authorization ─────────────────────────────────────────────────────────
    # Duration in seconds for a pending rehydration authorization prompt.
    authorization_prompt_timeout_seconds: int = Field(default=60)

    # ── OTP Provider ──────────────────────────────────────────────────────────
    # Provider abstraction point — pluggable without code changes.
    # Supported: "mock" (dev/test) | "twilio" | "fast2sms" (configure externally)
    otp_provider: str = Field(default="mock", alias="OTP_PROVIDER")
    otp_expiry_seconds: int = Field(default=300, alias="OTP_EXPIRY_SECONDS")

    def model_post_init(self, __context) -> None:
        if self.shade_env == "production":
            insecure_fallbacks = {
                "dev-insecure-secret-change-in-env",
                "test-jwt-secret-for-testing-only",
                "secret",
                "change-me",
            }
            if not self.shade_jwt_secret or self.shade_jwt_secret in insecure_fallbacks or len(self.shade_jwt_secret) < 32:
                raise ValueError(
                    "Production configuration error: SHADE_JWT_SECRET is missing, insecure, or shorter than 32 characters."
                )
            if self.otp_provider == "mock":
                raise ValueError(
                    "Production configuration error: Mock OTP provider ('mock') is strictly prohibited in production."
                )



@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached singleton settings instance."""
    return Settings()


# Module-level singleton for import convenience
settings = get_settings()
