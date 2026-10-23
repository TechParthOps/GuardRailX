"""Central application configuration (12-factor, environment-based)."""
from __future__ import annotations

import os
import secrets
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GX_", env_file=".env", extra="ignore")

    app_name: str = "GUARDRAIL-X"
    environment: str = "development"  # development | production
    data_dir: Path = Path("data")
    sandbox_dir: Path = Path("data/sandbox")
    database_url: str = ""  # empty -> derived sqlite path under data_dir
    session_ttl_minutes: int = 720
    api_key_ttl_days: int = 365
    admin_email: str = "admin@guardrailx.local"
    admin_password: str = ""  # if empty, generated once and written to data/initial_admin_password.txt
    secret_key: str = ""  # if empty, generated and persisted under data_dir
    log_level: str = "INFO"
    cors_origins: str = "*"  # dev convenience; set explicit origins in production
    # Orchestration limits
    max_concurrent_experiments: int = 4
    max_cases_per_experiment: int = 100
    case_timeout_seconds: int = 120
    case_replays: int = 2
    # Rate limiting (requests per minute per principal)
    rate_limit_per_minute: int = 600
    # OpenAI-compatible adapter (any provider speaking /v1/chat/completions)
    openai_api_key: str = ""
    openai_base_url: str = "https://api.openai.com/v1"
    openai_model: str = "gpt-4o-mini"
    openai_timeout_seconds: float = 60.0
    # Anthropic adapter
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-3-5-haiku-latest"
    anthropic_timeout_seconds: float = 60.0
    anthropic_version: str = "2023-06-01"
    # Adapters marked operational ONLY after a passing connection test
    require_connection_test: bool = True

    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite:///{(self.data_dir / 'guardrailx.db').as_posix()}"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.sandbox_dir.mkdir(parents=True, exist_ok=True)

    def get_or_create_secret(self) -> str:
        """Persistent secret for token hashing; never logged."""
        if self.secret_key:
            return self.secret_key
        self.ensure_dirs()
        key_file = self.data_dir / "secret_key"
        if key_file.exists():
            return key_file.read_text(encoding="utf-8").strip()
        key = secrets.token_urlsafe(48)
        key_file.write_text(key, encoding="utf-8")
        try:
            os.chmod(key_file, 0o600)
        except OSError:
            pass
        return key


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    s.ensure_dirs()
    return s
