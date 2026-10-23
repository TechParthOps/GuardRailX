"""Normalized, versioned data model (Module K).

JSON columns are used only for variable provider/trace/policy schemas;
everything else is a typed column with indexes and FKs.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (JSON, Boolean, DateTime, ForeignKey, Index,
                        Integer, String, Text, UniqueConstraint)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:20]}"


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ---------------------------------------------------------------- identity

class User(Base, TimestampMixin):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="viewer")  # admin|researcher|viewer
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False)


class AuthToken(Base, TimestampMixin):
    """Sessions and API keys; only hashes are stored.

    `role` is the credential's privilege CEILING at issuance; the effective
    role of a request is min(user's current role, token ceiling). `scopes`
    restricts project-level access: ["*"] or ["project:<id>", ...].
    """
    __tablename__ = "auth_tokens"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    kind: Mapped[str] = mapped_column(String(10), index=True)  # session|api_key
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    prefix: Mapped[str] = mapped_column(String(16), default="")
    name: Mapped[str] = mapped_column(String(120), default="")
    role: Mapped[str] = mapped_column(String(20), default="viewer")
    scopes: Mapped[list] = mapped_column(JSON, default=list)  # ["*"] or ["project:<id>"]
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class UserToken(Base, TimestampMixin):
    """Single-use account tokens (email verification, password reset)."""
    __tablename__ = "user_tokens"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    kind: Mapped[str] = mapped_column(String(24), index=True)  # verify_email|reset_password
    token_hash: Mapped[str] = mapped_column(String(128), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ProjectMember(Base, TimestampMixin):
    """Explicit project membership: the basis of resource-level isolation."""
    __tablename__ = "project_members"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    role: Mapped[str] = mapped_column(String(20), default="viewer")  # admin|researcher|viewer (project-level)

    __table_args__ = (UniqueConstraint("project_id", "user_id", name="uq_project_member"),)


class AuditEvent(Base, TimestampMixin):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    actor: Mapped[str] = mapped_column(String(255), index=True)
    action: Mapped[str] = mapped_column(String(120), index=True)
    object_type: Mapped[str] = mapped_column(String(60), default="")
    object_id: Mapped[str] = mapped_column(String(60), default="", index=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


# ------------------------------------------------------------- projects

class Project(Base, TimestampMixin):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)


# --------------------------------------------------------------- targets

class Target(Base, TimestampMixin):
    __tablename__ = "targets"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    adapter_name: Mapped[str] = mapped_column(String(60), index=True)
    model: Mapped[str] = mapped_column(String(160), default="")
    config: Mapped[dict] = mapped_column(JSON, default=dict)  # non-secret config only
    status: Mapped[str] = mapped_column(String(20), default="unverified")  # unverified|operational|failed
    last_health: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    __table_args__ = (UniqueConstraint("project_id", "name", name="uq_target_name"),)


# --------------------------------------------------------------- policy

class Policy(Base, TimestampMixin):
    __tablename__ = "policies"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    project_id: Mapped[str | None] = mapped_column(ForeignKey("projects.id"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(120))
    version: Mapped[int] = mapped_column(Integer, default=1)
    document: Mapped[dict] = mapped_column(JSON)
    active: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_by: Mapped[str] = mapped_column(String(40), default="")

    __table_args__ = (UniqueConstraint("name", "version", name="uq_policy_name_version"),)


# ------------------------------------------------------------- scenarios

class Scenario(Base, TimestampMixin):
    __tablename__ = "scenarios"
    key: Mapped[str] = mapped_column(String(120), primary_key=True)
    category: Mapped[str] = mapped_column(String(40), index=True)  # injection|jailbreak|tool|rag|policy|multimodal|regression
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    template: Mapped[dict] = mapped_column(JSON)  # messages/params/expected contract
    risk: Mapped[int] = mapped_column(Integer, default=30)
    source: Mapped[str] = mapped_column(String(20), default="builtin")  # builtin|custom|regression
    origin_finding_id: Mapped[str | None] = mapped_column(String(40), nullable=True)


# ------------------------------------------------------------ experiments

class Experiment(Base, TimestampMixin):
    __tablename__ = "experiments"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), index=True)
    policy_id: Mapped[str] = mapped_column(ForeignKey("policies.id"))
    title: Mapped[str] = mapped_column(String(200), default="")
    scenario_keys: Mapped[list] = mapped_column(JSON, default=list)
    config: Mapped[dict] = mapped_column(JSON, default=dict)  # limits, replays, dry_run, mode
    authorization: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="created", index=True)
    # created|running|paused|completed|cancelled|failed
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    stats: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_by: Mapped[str] = mapped_column(String(40), default="")
    adapter_version: Mapped[str] = mapped_column(String(20), default="")
    policy_version: Mapped[int] = mapped_column(Integer, default=1)
    target_model: Mapped[str] = mapped_column(String(160), default="")


class Case(Base, TimestampMixin):
    __tablename__ = "cases"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    experiment_id: Mapped[str] = mapped_column(ForeignKey("experiments.id"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    scenario_key: Mapped[str] = mapped_column(String(120), index=True)
    replay: Mapped[int] = mapped_column(Integer, default=0)
    trace_id: Mapped[str] = mapped_column(String(60), index=True)
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(24), default="pending")
    # pending|running|pass|model_violation|agent_attempted_blocked|agent_action_executed|enforcement_failure|inconclusive|inapplicable|infra_error|cancelled
    outcome: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    finding_id: Mapped[str | None] = mapped_column(String(40), nullable=True)

    __table_args__ = (Index("ix_cases_exp_seq", "experiment_id", "seq"),)


class EventRecord(Base, TimestampMixin):
    """Durable structured event store (Module I)."""
    __tablename__ = "events"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    experiment_id: Mapped[str | None] = mapped_column(String(40), index=True)
    case_id: Mapped[str | None] = mapped_column(String(40), index=True)
    trace_id: Mapped[str | None] = mapped_column(String(60), index=True)
    seq: Mapped[int] = mapped_column(Integer, default=0)
    type: Mapped[str] = mapped_column(String(60), index=True)
    actor: Mapped[str] = mapped_column(String(80), default="system")
    level: Mapped[str] = mapped_column(String(10), default="info")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)

    __table_args__ = (Index("ix_events_exp_seq", "experiment_id", "seq"),)


class Approval(Base, TimestampMixin):
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    experiment_id: Mapped[str] = mapped_column(String(40), index=True)
    case_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    tool_name: Mapped[str] = mapped_column(String(60))
    arguments: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)  # pending|approved|denied
    requested_by: Mapped[str] = mapped_column(String(80), default="agent")
    decided_by: Mapped[str | None] = mapped_column(String(80), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reason: Mapped[str] = mapped_column(Text, default="")


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    experiment_id: Mapped[str] = mapped_column(ForeignKey("experiments.id"), index=True)
    case_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    target_id: Mapped[str] = mapped_column(String(40), index=True)
    title: Mapped[str] = mapped_column(String(200))
    category: Mapped[str] = mapped_column(String(60), index=True)
    vuln_class: Mapped[str] = mapped_column(String(40), default="")
    # model_violation | agent_attempt | enforcement_failure | false_refusal | ...
    severity: Mapped[str] = mapped_column(String(12), default="medium")  # info|low|medium|high|critical
    confidence: Mapped[str] = mapped_column(String(12), default="medium")  # low|medium|high
    status: Mapped[str] = mapped_column(String(24), default="discovered", index=True)
    # discovered|evidence_collected|verification_pending|confirmed|rejected|inconclusive|remediation_proposed|regression_tested|closed
    expected: Mapped[dict] = mapped_column(JSON, default=dict)
    observed: Mapped[dict] = mapped_column(JSON, default=dict)
    preconditions: Mapped[list] = mapped_column(JSON, default=list)
    impact: Mapped[str] = mapped_column(Text, default="")
    likelihood: Mapped[str] = mapped_column(String(12), default="medium")
    limitations: Mapped[list] = mapped_column(JSON, default=list)
    remediation: Mapped[str] = mapped_column(Text, default="")
    evidence_event_ids: Mapped[list] = mapped_column(JSON, default=list)
    reproduction: Mapped[dict] = mapped_column(JSON, default=dict)
    failure_layer: Mapped[str] = mapped_column(String(24), default="model")  # model|agent|enforcement
    reproducible: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Regression(Base, TimestampMixin):
    __tablename__ = "regressions"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    scenario_key: Mapped[str] = mapped_column(String(120))
    template: Mapped[dict] = mapped_column(JSON)
    created_by: Mapped[str] = mapped_column(String(40), default="system")


class BenchmarkRun(Base, TimestampMixin):
    __tablename__ = "benchmark_runs"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    suite_key: Mapped[str] = mapped_column(String(60), index=True)
    target_id: Mapped[str] = mapped_column(String(40), index=True)
    project_id: Mapped[str] = mapped_column(String(40), index=True)
    policy_id: Mapped[str] = mapped_column(String(40))
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="created")
    metrics: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    experiment_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
