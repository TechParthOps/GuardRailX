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
    # --- identity bootstrap (secure setup; NO default admin identity) -------
    admin_email: str = ""      # set only by the operator via setup flow
    admin_password: str = ""   # consumed by setup flow; never persisted
    setup_token: str = ""      # one-time token guarding POST /api/v1/setup (web bootstrap)
    # --- account policies ---------------------------------------------------
    allow_signup: bool = True              # public registration toggle
    require_email_verification: bool = False  # enable for production with SMTP delivery
    allow_password_reset: bool = True      # self-serve reset; requires delivery when enabled
    # --- account-token delivery (Phase 5) -----------------------------------
    email_mode: str = "console"            # console (dev) | smtp
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_use_tls: bool = True              # STARTTLS
    smtp_use_ssl: bool = False             # implicit TLS (port 465)
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = "guardrailx@localhost"
    smtp_timeout_seconds: float = 15.0
    verification_token_ttl_minutes: int = 60 * 24
    reset_token_ttl_minutes: int = 60
    # --- content & seeding --------------------------------------------------
    seed_demo_data: bool = False           # demo project/experiment; OFF by default
    enable_docs: bool | None = None        # None -> enabled in development, disabled in production
    secret_key: str = ""  # if empty, generated and persisted under data_dir
    log_level: str = "INFO"
    cors_origins: str = "*"  # dev convenience; set explicit origins in production
    # --- outbound provider security (GX-003) --------------------------------
    allowed_key_envs: str = "OPENAI_API_KEY,ANTHROPIC_API_KEY,GEMINI_API_KEY,NVIDIA_API_KEY"
    allowed_endpoint_hosts: str = ""       # admin-approved extra hosts (comma-separated)
    allow_local_endpoints: bool = False    # explicit opt-in for loopback/private model servers
    # --- orchestration limits
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

    @property
    def docs_enabled(self) -> bool:
        if self.enable_docs is not None:
            return self.enable_docs
        return self.environment != "production"

    def production_config_errors(self) -> list[str]:
        """Critical configuration that must be present before production serving."""
        errors = []
        if self.environment != "production":
            return errors
        if not self.secret_key:
            errors.append("GX_SECRET_KEY must be set explicitly in production")
        elif len(self.secret_key) < 32:
            errors.append("GX_SECRET_KEY is too short for production (use >= 32 random bytes, "
                          "e.g. python -c \"import secrets; print(secrets.token_urlsafe(48))\")")
        if self.cors_origins == "*":
            errors.append("GX_CORS_ORIGINS must list explicit trusted origins in production")
        if self.seed_demo_data:
            errors.append("GX_SEED_DEMO_DATA must be false in production")
        # Priority 0: ANY enabled account-token workflow needs secure delivery.
        # Password reset is enabled by default, so production must configure
        # SMTP — or explicitly disable the reset workflow.
        if (self.require_email_verification or self.allow_password_reset
                or self.email_mode == "smtp"):
            from app.mailer import delivery_ready
            ok, why = delivery_ready()
            if not ok:
                errors.append(f"account-token delivery misconfigured: {why}")
        return errors

    def allowed_key_envs_list(self) -> list[str]:
        return [x.strip() for x in self.allowed_key_envs.split(",") if x.strip()]

    def allowed_endpoint_hosts_list(self) -> list[str]:
        return [x.strip().lower() for x in self.allowed_endpoint_hosts.split(",") if x.strip()]

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
