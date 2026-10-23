"""API request schemas (input validation boundary)."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

_EMAIL_RE = r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$"


class LoginRequest(BaseModel):
    model_config = {"extra": "forbid"}

    email: str = Field(min_length=3, max_length=255, pattern=_EMAIL_RE)
    password: str = Field(min_length=1, max_length=256)


class SignupRequest(BaseModel):
    model_config = {"extra": "forbid"}

    email: str = Field(min_length=3, max_length=255, pattern=_EMAIL_RE)
    password: str = Field(min_length=12, max_length=256)
    password_confirm: str = Field(min_length=12, max_length=256)


class VerifyEmailRequest(BaseModel):
    model_config = {"extra": "forbid"}

    token: str = Field(min_length=16, max_length=256)


class RequestResetRequest(BaseModel):
    model_config = {"extra": "forbid"}

    email: str = Field(min_length=3, max_length=255, pattern=_EMAIL_RE)


class ResetPasswordRequest(BaseModel):
    model_config = {"extra": "forbid"}

    token: str = Field(min_length=16, max_length=256)
    password: str = Field(min_length=12, max_length=256)


class ChangePasswordRequest(BaseModel):
    model_config = {"extra": "forbid"}

    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


class CreateUserRequest(BaseModel):
    model_config = {"extra": "forbid"}

    email: str = Field(min_length=3, max_length=255, pattern=_EMAIL_RE)
    password: str = Field(min_length=12, max_length=256)
    role: str = Field(default="viewer", pattern="^(admin|researcher|viewer)$")


class RoleChangeRequest(BaseModel):
    model_config = {"extra": "forbid"}

    role: str = Field(pattern="^(admin|researcher|viewer)$")
    revoke_credentials: bool = True


class DisableRequest(BaseModel):
    model_config = {"extra": "forbid"}

    disabled: bool


class SetupRequest(BaseModel):
    model_config = {"extra": "forbid"}

    setup_token: str = Field(min_length=16, max_length=256)
    email: str = Field(min_length=3, max_length=255, pattern=_EMAIL_RE)
    password: str = Field(min_length=12, max_length=256)


class ApiKeyRequest(BaseModel):
    model_config = {"extra": "forbid"}

    name: str = Field(min_length=1, max_length=120)
    role: str | None = Field(default=None, pattern="^(admin|researcher|viewer)$")
    scopes: list[str] | None = Field(default=None, max_length=20)


class ProjectRequest(BaseModel):
    model_config = {"extra": "forbid"}

    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)


class MemberRequest(BaseModel):
    model_config = {"extra": "forbid"}

    email: str = Field(min_length=3, max_length=255, pattern=_EMAIL_RE)
    role: str = Field(pattern="^(admin|researcher|viewer)$")


class TargetRequest(BaseModel):
    model_config = {"extra": "forbid"}

    project_id: str = Field(min_length=1, max_length=40)
    name: str = Field(min_length=1, max_length=120)
    adapter_name: str = Field(min_length=1, max_length=60)
    model: str = Field(default="", max_length=160)
    config: dict[str, Any] = Field(default_factory=dict)

    @field_validator("config")
    @classmethod
    def no_secrets(cls, v: dict[str, Any]) -> dict[str, Any]:
        forbidden = {"api_key", "apikey", "secret", "password", "token", "authorization"}
        for k in v:
            if str(k).lower() in forbidden:
                raise ValueError(f"field '{k}' must never be stored in target config; use env vars")
        return v


class PolicyRequest(BaseModel):
    model_config = {"extra": "forbid"}

    project_id: str | None = None
    name: str = Field(min_length=1, max_length=120)
    document: dict[str, Any]


class PolicyEvaluateRequest(BaseModel):
    model_config = {"extra": "forbid"}

    policy_id: str
    tool_name: str = Field(min_length=1, max_length=60)
    arguments: dict[str, Any] = Field(default_factory=dict)


class ExperimentRequest(BaseModel):
    model_config = {"extra": "forbid"}

    project_id: str
    target_id: str
    policy_id: str
    scenario_keys: list[str] = Field(min_length=1)
    title: str = Field(default="", max_length=200)
    authorization: dict[str, Any]
    config: dict[str, Any] = Field(default_factory=dict)

    @field_validator("scenario_keys")
    @classmethod
    def dedupe(cls, v: list[str]) -> list[str]:
        return list(dict.fromkeys(v))


class ApproveRequest(BaseModel):
    model_config = {"extra": "forbid"}

    decision: str = Field(pattern="^(approved|denied)$")
    reason: str = Field(default="", max_length=500)


class RedTeamRequest(BaseModel):
    model_config = {"extra": "forbid"}

    base_scenario_keys: list[str] = Field(min_length=1, max_length=10)
    variations_per_base: int = Field(default=3, ge=1, le=8)


class BenchmarkRequest(BaseModel):
    model_config = {"extra": "forbid"}

    project_id: str
    target_id: str
    policy_id: str
    suite_key: str = Field(min_length=1, max_length=60)
    authorization: dict[str, Any]
    config: dict[str, Any] = Field(default_factory=dict)


class CustomScenarioRequest(BaseModel):
    model_config = {"extra": "forbid"}

    key: str = Field(min_length=3, max_length=120, pattern="^custom\\.[a-z0-9._-]+$")
    category: str = Field(pattern="^(injection|jailbreak|tool|rag|policy|multimodal)$")
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    risk: int = Field(default=30, ge=0, le=100)
    template: dict[str, Any]
