"""Central configuration, loaded from environment / .env with safe defaults."""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AEGIS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # App
    env: str = "development"
    debug: bool = True

    # Security
    secret_key: str = "dev-insecure-change-me"
    access_token_ttl_minutes: int = 1440
    jwt_algorithm: str = "HS256"

    # Database
    database_url: str = "sqlite:///./aegisscan.db"

    # CORS (regex so one rule matches every preview hostname)
    cors_allow_origin_regex: str = (
        r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$"
        r"|^https://([a-z0-9-]+\.)*vercel\.app$"
    )

    # Scan engine
    scan_timeout_seconds: float = 10.0
    scan_total_budget_seconds: float = 25.0
    allow_private_targets: bool = False
    rate_limit_per_minute: int = 20

    # Public dashboard masking
    public_benchmarks: str = "github.com,stripe.com,cloudflare.com,google.com,mozilla.org"

    # Observability
    sentry_dsn: str = ""

    @property
    def benchmark_set(self) -> set[str]:
        return {h.strip().lower() for h in self.public_benchmarks.split(",") if h.strip()}

    @property
    def is_production(self) -> bool:
        return self.env == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
