"""Module L — versioned REST API (v1).

All mutating endpoints require authentication and RBAC. Privileged admin
operations (policies activation, emergency stop, users) require 'admin'.
Rate limiting and secret redaction are applied at the app level.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import defaultdict, deque
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select

from app.api import schemas as S
from app.auth import service as authsvc
from app.auth.service import Principal, require_admin, require_researcher, require_viewer
from app.benchmarks import runner as bench
from app.config import get_settings
from app.db import session_scope
from app.experiments import orchestrator as orch
from app.experiments import redteam as rt
from app.experiments.findings import verify_finding
from app.models import (Approval, BenchmarkRun, Case, EventRecord, Experiment,
                        Finding, Policy, Project, ProjectMember, Regression, Scenario, Target,
                        User, new_id, utcnow)
from app.observability.bus import bus
from app.observability.events import event_to_dict, record_event
from app.observability.redaction import redact_obj
from app.policy.engine import policy_engine, DEFAULT_POLICY_DOCUMENT, validate_policy_document, document_hash
from app.scenarios.library import CATEGORIES, get_builtin_scenarios
from app.tools import builtin

log = logging.getLogger("guardrailx.api")
router = APIRouter(prefix="/api/v1")


# ------------------------------------------------------------------- health

@router.get("/health", tags=["system"])
def health() -> dict[str, Any]:
    return {"status": "ok", "app": get_settings().app_name, "environment": get_settings().environment}


@router.get("/ready", tags=["system"])
def ready() -> dict[str, Any]:
    from app.db import engine
    db_ok = False
    try:
        from sqlalchemy import text as _t
        with engine.connect() as conn:
            conn.execute(_t("SELECT 1"))
        db_ok = True
    except Exception:
        pass
    return {"database": db_ok, "emergency_stop": orch.emergency_stop_active(),
            "experiments_running": len(orch.EXPERIMENT_TASKS)}


# --------------------------------------------------------------------- setup

@router.post("/setup", tags=["setup"])
def web_setup(body: S.SetupRequest) -> dict[str, Any]:
    """One-time administrator bootstrap. Works only while no admin exists and
    only with the operator-provisioned GX_SETUP_TOKEN. Audited; fails closed."""
    from app.setup import setup_from_token
    try:
        u = setup_from_token(body.setup_token, body.email, body.password)
    except PermissionError as exc:
        raise HTTPException(403, str(exc))
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    return {"ok": True, "email": u.email, "message": "administrator created; sign in now"}


@router.get("/setup/status", tags=["setup"])
def setup_status() -> dict[str, Any]:
    """Used by the UI to decide whether to show the setup wizard.

    setup_required = NO ACTIVE ADMINISTRATOR exists (single shared definition
    with the setup handler; a registered viewer without an admin still counts
    as "setup required").
    """
    from app.setup import _setup_completed
    return {"setup_required": not _setup_completed(),
            "signup_enabled": get_settings().allow_signup}


# --------------------------------------------------------------------- auth

_rate_store: dict[str, deque] = defaultdict(deque)


def auth_rate_limit(bucket: str, limit_per_minute: int = 10):
    """Per-route sliding-window limiter keyed by (bucket, client IP).

    In-memory by design for the single-process deployment; multi-worker
    deployments need a shared store (documented limitation).
    """
    def dep(request: Request) -> None:
        client = request.client.host if request.client else "unknown"
        key = f"{bucket}:{client}"
        window = _rate_store[key]
        now = time.monotonic()
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= limit_per_minute:
            authsvc.audit(client, "authz.rate_limited", "endpoint", bucket)
            raise HTTPException(429, "too many attempts; try again later")
        window.append(now)
    return dep


def _require_email_verified(user) -> None:
    """When email verification is enforced, block unverified logins (generic message)."""
    if get_settings().require_email_verification and not user.email_verified:
        raise HTTPException(403, "account requires verification before sign-in")


@router.post("/auth/login", tags=["auth"])
def login(body: S.LoginRequest, _rl: None = Depends(auth_rate_limit("login", 10))) -> dict[str, Any]:
    user, token = authsvc.authenticate(body.email, body.password)
    if not user:
        authsvc.audit(authsvc.normalize_email(body.email) if "@" in body.email else body.email,
                      "auth.login_failed")
        raise HTTPException(401, "invalid credentials")  # generic: no user enumeration
    _require_email_verified(user)
    authsvc.audit(user.email, "auth.login")
    return {"access_token": token, "token_type": "bearer",
            "role": getattr(user, "_effective_role", user.role), "email": user.email,
            "email_verified": bool(user.email_verified)}


@router.post("/auth/signup", tags=["auth"], status_code=201)
def signup(body: S.SignupRequest, _rl: None = Depends(auth_rate_limit("signup", 10))) -> dict[str, Any]:
    """Public registration. Always assigns the lowest-privilege role; a role can
    only be granted afterwards by an administrator. Disabled by config in
    closed deployments (GX_ALLOW_SIGNUP=false)."""
    if not get_settings().allow_signup:
        raise HTTPException(403, "registration is disabled on this deployment")
    if body.password != body.password_confirm:
        raise HTTPException(422, "passwords do not match")
    policy = authsvc.password_policy_error(body.password)
    if policy:
        raise HTTPException(422, policy)
    try:
        u = authsvc.create_user(body.email, body.password, role="viewer")
    except ValueError:
        authsvc.audit("signup", "auth.signup_duplicate", "email", "")
        raise HTTPException(409, "registration failed: account may already exist")
    authsvc.audit(u.email, "auth.signup", "user", u.id, {"role": "viewer"})
    if get_settings().require_email_verification:
        raw = authsvc.issue_user_token(u.id, "verify_email", ttl_minutes=60 * 24)
        _deliver_account_token(u.email, "verify_email", raw)
        return {"ok": True, "email": u.email, "verification_required": True,
                "message": "check your email (or operator console) for the verification token"}
    return {"ok": True, "email": u.email, "verification_required": False}


@router.post("/auth/verify-email", tags=["auth"])
def verify_email(body: S.VerifyEmailRequest, _rl: None = Depends(auth_rate_limit("verify", 20))) -> dict[str, Any]:
    uid = authsvc.consume_user_token(body.token, "verify_email")
    if not uid:
        raise HTTPException(400, "invalid or expired verification token")
    with session_scope() as s:
        u = s.get(authsvc.User, uid)
        if u:
            u.email_verified = True
    authsvc.audit(uid, "auth.email_verified", "user", uid)
    return {"ok": True}


@router.post("/auth/resend-verification", tags=["auth"])
def resend_verification(body: S.RequestResetRequest, _rl: None = Depends(auth_rate_limit("verify", 10))) -> dict[str, Any]:
    """Generic response regardless of account existence (no enumeration)."""
    try:
        e = authsvc.normalize_email(body.email)
    except ValueError:
        raise HTTPException(422, "invalid email address")
    with session_scope() as s:
        u = s.scalar(select(authsvc.User).where(authsvc.User.email == e))
        if u and not u.email_verified:
            raw = authsvc.issue_user_token(u.id, "verify_email", ttl_minutes=60 * 24)
            _deliver_account_token(u.email, "verify_email", raw)
    return {"ok": True, "message": "if the account exists and is unverified, a token was issued"}


@router.post("/auth/request-password-reset", tags=["auth"])
def request_password_reset(body: S.RequestResetRequest, _rl: None = Depends(auth_rate_limit("reset", 10))) -> dict[str, Any]:
    """Always returns a generic response (no account enumeration)."""
    try:
        e = authsvc.normalize_email(body.email)
    except ValueError:
        return {"ok": True, "message": "if the account exists, a reset token was issued"}
    with session_scope() as s:
        u = s.scalar(select(authsvc.User).where(authsvc.User.email == e, authsvc.User.disabled == False))  # noqa: E712
        if u:
            raw = authsvc.issue_user_token(u.id, "reset_password", ttl_minutes=60)
            _deliver_account_token(u.email, "reset_password", raw)
            authsvc.audit(u.email, "auth.reset_requested", "user", u.id)
    return {"ok": True, "message": "if the account exists, a reset token was issued"}


@router.post("/auth/reset-password", tags=["auth"])
def reset_password(body: S.ResetPasswordRequest, _rl: None = Depends(auth_rate_limit("reset", 10))) -> dict[str, Any]:
    policy = authsvc.password_policy_error(body.password)
    if policy:
        raise HTTPException(422, policy)
    uid = authsvc.consume_user_token(body.token, "reset_password")
    if not uid:
        raise HTTPException(400, "invalid or expired reset token")
    with session_scope() as s:
        u = s.get(authsvc.User, uid)
        if not u or u.disabled:
            raise HTTPException(400, "invalid or expired reset token")
        u.password_hash = authsvc.hash_password(body.password)
    authsvc.revoke_user_credentials(uid)  # password change invalidates every session/key
    authsvc.audit(uid, "auth.password_reset", "user", uid, {"sessions_revoked": True})
    return {"ok": True, "message": "password updated; sign in again"}


@router.post("/auth/change-password", tags=["auth"])
def change_password(body: S.ChangePasswordRequest,
                    principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
    if not authsvc.verify_password(body.current_password, principal.user.password_hash):
        raise HTTPException(401, "current password incorrect")
    policy = authsvc.password_policy_error(body.new_password)
    if policy:
        raise HTTPException(422, policy)
    with session_scope() as s:
        u = s.get(authsvc.User, principal.id)
        u.password_hash = authsvc.hash_password(body.new_password)
    authsvc.revoke_user_credentials(principal.id)
    authsvc.audit(principal.email, "auth.password_changed", "user", principal.id,
                  {"sessions_revoked": True})
    return {"ok": True, "message": "password updated; all sessions revoked"}


@router.post("/auth/logout", tags=["auth"])
def logout(principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
    with session_scope() as s:
        at = s.get(authsvc.AuthToken, principal.token.id)
        if at:
            at.revoked = True
    authsvc.audit(principal.email, "auth.logout")
    return {"ok": True}


@router.post("/auth/revoke-all", tags=["auth"])
def revoke_all_sessions(principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
    n = authsvc.revoke_user_credentials(principal.id)
    authsvc.audit(principal.email, "auth.revoked_all", "user", principal.id, {"revoked": n})
    return {"ok": True, "revoked": n}


@router.get("/auth/me", tags=["auth"])
def me(principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
    return {"email": principal.email, "role": principal.role, "user_id": principal.id,
            "scopes": principal.scopes}


@router.post("/auth/users", tags=["auth"])
def create_user(body: S.CreateUserRequest, principal: Principal = Depends(require_admin)) -> dict[str, Any]:
    policy = authsvc.password_policy_error(body.password)
    if policy:
        raise HTTPException(422, policy)
    try:
        u = authsvc.create_user(body.email, body.password, body.role, email_verified=True)
    except ValueError:
        raise HTTPException(409, "user already exists")
    authsvc.audit(principal.email, "user.created", "user", u.id, {"role": body.role})
    return {"id": u.id, "email": u.email, "role": u.role}


@router.post("/auth/api-keys", tags=["auth"])
def create_api_key(body: S.ApiKeyRequest, principal: Principal = Depends(require_researcher)) -> dict[str, Any]:
    """Ceiling-enforced key minting (GX-001 fix). Key material shown exactly once."""
    try:
        token, at = authsvc.create_api_key(principal, body.name, body.role, body.scopes)
    except PermissionError as exc:
        raise HTTPException(403, str(exc))
    return {"api_key": token, "prefix": at.prefix, "role": at.role, "scopes": at.scopes,
            "note": "store securely; it is shown only once and stored only as a hash"}


@router.get("/auth/api-keys", tags=["auth"])
def list_api_keys(principal: Principal = Depends(require_viewer)) -> list[dict[str, Any]]:
    with session_scope() as s:
        rows = s.scalars(select(authsvc.AuthToken).where(
            authsvc.AuthToken.kind == "api_key", authsvc.AuthToken.user_id == principal.id,
            authsvc.AuthToken.revoked == False)).all()  # noqa: E712
        return [{"id": r.id, "name": r.name, "prefix": r.prefix, "role": r.role,
                 "scopes": r.scopes, "created_at": str(r.created_at)} for r in rows]


@router.delete("/auth/api-keys/{key_id}", tags=["auth"])
def revoke_api_key(key_id: str, principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
    with session_scope() as s:
        at = s.get(authsvc.AuthToken, key_id)
        if not at or at.kind != "api_key" or (at.user_id != principal.id and principal.role != "admin"):
            raise HTTPException(404, "api key not found")
        at.revoked = True
    authsvc.audit(principal.email, "api_key.revoked", "api_key", key_id)
    return {"ok": True}


# --------------------------------------------------- account-token delivery

def _deliver_account_token(email: str, kind: str, raw_token: str) -> None:
    """Real delivery (Phase 5). Failures raise so the endpoint never claims
    success. Tokens never appear in logs, audit records, or API responses."""
    from app.mailer import DeliveryError, send_account_token
    try:
        send_account_token(email, kind, raw_token)
    except DeliveryError as exc:
        raise HTTPException(503, str(exc))


# ------------------------------------------------------- resource isolation

def _accessible_project_ids(principal: Principal) -> list[str] | Literal["all"]:
    """Project IDs the principal may see. 'all' for platform administrators."""
    if principal.role == "admin" and "*" in principal.scopes:
        return "all"
    with session_scope() as s:
        owned = s.scalars(select(Project.id).where(Project.owner_id == principal.id)).all()
        member = s.scalars(select(ProjectMember.project_id)
                           .where(ProjectMember.user_id == principal.id)).all()
    scoped = [x.split("project:", 1)[1] for x in principal.scopes
              if x.startswith("project:")]
    if scoped:
        allowed = set(owned) | set(member)
        return sorted(allowed & set(scoped))
    return sorted(set(owned) | set(member))


def _project_role_or_404(principal: Principal, project_id: str, minimum: str = "viewer") -> str:
    role = authsvc.project_access(principal, project_id)
    if role is None or authsvc.ROLE_RANK.get(role, -1) < authsvc.ROLE_RANK[minimum]:
        authsvc.audit(principal.email, "authz.project_denied", "project", project_id,
                      {"required": minimum})
        raise HTTPException(404, "resource not found")  # 404 (not 403): no enumeration
    return role


def _authorize_target(principal: Principal, target_id: str, minimum: str = "viewer") -> Target:
    with session_scope() as s:
        t = s.get(Target, target_id)
        if not t:
            raise HTTPException(404, "target not found")
        project_id = t.project_id
    _project_role_or_404(principal, project_id, minimum)
    return t


def _authorize_experiment(principal: Principal, experiment_id: str,
                          minimum: str = "viewer") -> Experiment:
    with session_scope() as s:
        e = s.get(Experiment, experiment_id)
        if not e:
            raise HTTPException(404, "experiment not found")
        project_id = e.project_id
    _project_role_or_404(principal, project_id, minimum)
    return e


def _authorize_finding(principal: Principal, finding_id: str) -> Finding:
    with session_scope() as s:
        f = s.get(Finding, finding_id)
        if not f:
            raise HTTPException(404, "finding not found")
        e = s.get(Experiment, f.experiment_id)
        project_id = e.project_id if e else None
    if project_id is None:
        raise HTTPException(404, "finding not found")
    _project_role_or_404(principal, project_id, "viewer")
    return f


def _authorize_policy(principal: Principal, policy_id: str, minimum: str = "viewer") -> Policy:
    with session_scope() as s:
        p = s.get(Policy, policy_id)
        if not p:
            raise HTTPException(404, "policy not found")
        project_id = p.project_id
    if project_id is None:  # global security policy: visible to authenticated users
        return p
    _project_role_or_404(principal, project_id, minimum)
    return p


def _validate_experiment_resources(project_id: str, target_id: str, policy_id: str) -> None:
    """Reject mismatched resource combinations (Part 4.2)."""
    with session_scope() as s:
        t = s.get(Target, target_id)
        if not t or t.project_id != project_id:
            raise HTTPException(400, "target does not belong to the project")
        p = s.get(Policy, policy_id)
        if not p or (p.project_id is not None and p.project_id != project_id):
            raise HTTPException(400, "policy does not belong to the project")



# ----------------------------------------------------------------- projects

@router.get("/projects", tags=["projects"])
def list_projects(principal: Principal = Depends(require_viewer)) -> list[dict[str, Any]]:
    accessible = _accessible_project_ids(principal)
    with session_scope() as s:
        q = select(Project)
        if accessible != "all":
            if not accessible:
                return []
            q = q.where(Project.id.in_(accessible))
        rows = s.scalars(q).all()
        return [{"id": p.id, "name": p.name, "description": p.description,
                 "is_demo": p.is_demo, "owner_id": p.owner_id} for p in rows]


@router.post("/projects", tags=["projects"])
def create_project(body: S.ProjectRequest, principal: Principal = Depends(require_researcher)) -> dict[str, Any]:
    with session_scope() as s:
        if s.scalar(select(Project).where(Project.name == body.name)):
            raise HTTPException(409, "project name exists")
        p = Project(id=new_id("prj"), name=body.name, description=body.description, owner_id=principal.id)
        s.add(p)
        s.flush()
        s.add(ProjectMember(id=new_id("pm"), project_id=p.id, user_id=principal.id, role="admin"))
        authsvc.audit(principal.email, "project.created", "project", p.id, session=s)
        return {"id": p.id, "name": p.name}


@router.get("/projects/{project_id}/members", tags=["projects"])
def list_members(project_id: str, principal: Principal = Depends(require_viewer)) -> list[dict[str, Any]]:
    _project_role_or_404(principal, project_id, "viewer")
    with session_scope() as s:
        rows = s.scalars(select(ProjectMember).where(ProjectMember.project_id == project_id)).all()
        out = []
        for m in rows:
            u = s.get(authsvc.User, m.user_id)
            out.append({"id": m.id, "user_id": m.user_id,
                        "email": u.email if u else "(deleted)", "role": m.role})
        return out


@router.post("/projects/{project_id}/members", tags=["projects"])
def add_member(project_id: str, body: S.MemberRequest,
               principal: Principal = Depends(require_researcher)) -> dict[str, Any]:
    """Project admins add members; membership can never exceed the grantor's
    project role, and platform admins are required for admin-level grants."""
    role = _project_role_or_404(principal, project_id, "researcher")
    if body.role == "admin" and principal.role != "admin" and role != "admin":
        raise HTTPException(403, "only administrators may grant project-admin membership")
    if authsvc.ROLE_RANK.get(body.role, -1) > authsvc.ROLE_RANK.get(role, -1) \
            and principal.role != "admin":
        raise HTTPException(403, "cannot grant a membership above your project role")
    with session_scope() as s:
        u = s.scalar(select(authsvc.User).where(authsvc.User.email == body.email.lower()))
        if not u:
            raise HTTPException(404, "user not found")
        if s.scalar(select(ProjectMember).where(ProjectMember.project_id == project_id,
                                                ProjectMember.user_id == u.id)):
            raise HTTPException(409, "already a member")
        s.add(ProjectMember(id=new_id("pm"), project_id=project_id, user_id=u.id, role=body.role))
        authsvc.audit(principal.email, "project.member_added", "project", project_id,
                      {"user": u.email, "role": body.role}, session=s)
        return {"ok": True, "user_id": u.id, "role": body.role}


@router.delete("/projects/{project_id}/members/{user_id}", tags=["projects"])
def remove_member(project_id: str, user_id: str,
                  principal: Principal = Depends(require_researcher)) -> dict[str, Any]:
    role = _project_role_or_404(principal, project_id, "researcher")
    with session_scope() as s:
        m = s.scalar(select(ProjectMember).where(ProjectMember.project_id == project_id,
                                                 ProjectMember.user_id == user_id))
        if not m:
            raise HTTPException(404, "member not found")
        if m.role == "admin" and role != "admin" and principal.role != "admin":
            raise HTTPException(403, "cannot remove a project admin")
        s.delete(m)
    authsvc.audit(principal.email, "project.member_removed", "project", project_id, {"user_id": user_id})
    return {"ok": True}


# ----------------------------------------------------------------- targets

@router.get("/adapters", tags=["targets"])
def list_adapters(principal: Principal = Depends(require_viewer)) -> list[dict[str, Any]]:
    from app.adapters.registry import registry
    return registry.list()


@router.get("/targets", tags=["targets"])
def list_targets(project_id: str | None = None, principal: Principal = Depends(require_viewer)) -> list[dict[str, Any]]:
    accessible = _accessible_project_ids(principal)
    with session_scope() as s:
        q = select(Target)
        if project_id:
            _project_role_or_404(principal, project_id, "viewer")
            q = q.where(Target.project_id == project_id)
        elif accessible != "all":
            if not accessible:
                return []
            q = q.where(Target.project_id.in_(accessible))
        rows = s.scalars(q).all()
        return [{"id": t.id, "project_id": t.project_id, "name": t.name, "adapter_name": t.adapter_name,
                 "model": t.model, "status": t.status, "last_health": t.last_health,
                 "config": t.config, "is_demo": _project_is_demo(s, t.project_id)} for t in rows]


def _project_is_demo(s, project_id: str) -> bool:
    p = s.get(Project, project_id)
    return bool(p and p.is_demo)


@router.post("/targets", tags=["targets"])
def create_target(body: S.TargetRequest, principal: Principal = Depends(require_researcher)) -> dict[str, Any]:
    from app.adapters.registry import registry
    _project_role_or_404(principal, body.project_id, "researcher")
    try:
        adapter = registry.get(body.adapter_name)
    except KeyError as exc:
        raise HTTPException(400, str(exc))
    ok, detail = adapter.validate_config_secure(body.config | ({"model": body.model} if body.model else {}))
    if not ok:
        raise HTTPException(400, f"adapter config invalid: {detail}")
    with session_scope() as s:
        if not s.get(Project, body.project_id):
            raise HTTPException(404, "project not found")
        if s.scalar(select(Target).where(Target.project_id == body.project_id, Target.name == body.name)):
            raise HTTPException(409, "target name exists in project")
        t = Target(id=new_id("tgt"), project_id=body.project_id, name=body.name,
                   adapter_name=body.adapter_name, model=body.model, config=body.config,
                   status="unverified")
        s.add(t)
        s.flush()
        authsvc.audit(principal.email, "target.created", "target", t.id, session=s,
                      detail={"adapter": body.adapter_name, "model": body.model})
        return {"id": t.id, "name": t.name, "status": t.status}


@router.get("/targets/{target_id}", tags=["targets"])
def get_target(target_id: str, principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
    t = _authorize_target(principal, target_id, "viewer")
    with session_scope() as s:
        t2 = s.get(Target, target_id)
        return {"id": t2.id, "project_id": t2.project_id, "name": t2.name,
                "adapter_name": t2.adapter_name, "model": t2.model, "status": t2.status,
                "last_health": t2.last_health, "config": t2.config,
                "is_demo": _project_is_demo(s, t2.project_id)}


@router.post("/targets/{target_id}/test-connection", tags=["targets"])
def test_connection(target_id: str, principal: Principal = Depends(require_researcher)) -> dict[str, Any]:
    """REAL connection test; target becomes operational only on success."""
    from app.adapters.registry import registry
    t = _authorize_target(principal, target_id, "researcher")
    with session_scope() as s:
        result = registry.test_connection(t.adapter_name, t.config | ({"model": t.model} if t.model else {}))
        t2 = s.get(Target, target_id)
        t2.status = "operational" if result.ok else "failed"
        t2.last_health = {"ok": result.ok, "detail": result.detail, "latency_ms": result.latency_ms,
                          "tested_at": str(utcnow())}
        record_event(s, experiment_id=None, type_="target.health", actor=principal.email,
                     payload={"target": t2.name, "adapter": t2.adapter_name,
                              "ok": result.ok, "detail": result.detail})
        authsvc.audit(principal.email, "target.connection_tested", "target", t2.id,
                      {"ok": result.ok, "detail": result.detail}, session=s)
        return {"target_id": t2.id, "status": t2.status, "health": t2.last_health}


@router.delete("/targets/{target_id}", tags=["targets"])
def delete_target(target_id: str, principal: Principal = Depends(require_researcher)) -> dict[str, Any]:
    t = _authorize_target(principal, target_id, "researcher")
    with session_scope() as s:
        t2 = s.get(Target, target_id)
        linked = s.query(Experiment).filter(Experiment.target_id == target_id).count()
        if linked:
            raise HTTPException(409,
                                f"target has {linked} linked experiments; "
                                "targets referenced by experiment records are retained for evidence integrity")
        s.delete(t2)
    authsvc.audit(principal.email, "target.deleted", "target", target_id)
    return {"ok": True}


# ---------------------------------------------------------------- policies

@router.get("/policies", tags=["policy"])
def list_policies(principal: Principal = Depends(require_viewer)) -> list[dict[str, Any]]:
    accessible = _accessible_project_ids(principal)
    with session_scope() as s:
        rows = s.scalars(select(Policy).order_by(Policy.name, Policy.version.desc())).all()
        out = []
        for p in rows:
            if p.project_id is not None and accessible != "all" and p.project_id not in accessible:
                continue
            out.append({"id": p.id, "name": p.name, "version": p.version, "active": p.active,
                        "project_id": p.project_id, "document": p.document,
                        "document_hash": document_hash(p.document)})
        return out


@router.post("/policies", tags=["policy"])
def create_policy(body: S.PolicyRequest, principal: Principal = Depends(require_admin)) -> dict[str, Any]:
    ok, detail = validate_policy_document(body.document)
    if not ok:
        raise HTTPException(400, f"invalid policy: {detail}")
    if body.project_id:
        _project_role_or_404(principal, body.project_id, "admin")
    with session_scope() as s:
        prev = s.scalars(select(Policy).where(Policy.name == body.name)).all()
        version = max((p.version for p in prev), default=0) + 1
        p = Policy(id=new_id("pol"), project_id=body.project_id, name=body.name,
                   version=version, document=body.document, active=False, created_by=principal.id)
        s.add(p)
        s.flush()
        policy_engine.load(p.id, version, body.document)
        authsvc.audit(principal.email, "policy.created", "policy", p.id, {"version": version}, session=s)
        return {"id": p.id, "name": p.name, "version": version, "active": p.active}


@router.post("/policies/{policy_id}/activate", tags=["policy"])
def activate_policy(policy_id: str, principal: Principal = Depends(require_admin)) -> dict[str, Any]:
    with session_scope() as s:
        p = s.get(Policy, policy_id)
        if not p:
            raise HTTPException(404, "policy not found")
        s.query(Policy).filter(Policy.name == p.name).update({Policy.active: False})
        p.active = True
        policy_engine.load(p.id, p.version, p.document)
        authsvc.audit(principal.email, "policy.activated", "policy", p.id, {"version": p.version}, session=s)
        return {"id": p.id, "active": True, "version": p.version}


@router.post("/policies/evaluate", tags=["policy"])
def evaluate_policy(body: S.PolicyEvaluateRequest, principal: Principal = Depends(require_researcher)) -> dict[str, Any]:
    """Dry-run a policy decision without executing anything."""
    _authorize_policy(principal, body.policy_id, "viewer")
    with session_scope() as s:
        p = s.get(Policy, body.policy_id)
        policy_engine.load(p.id, p.version, p.document)
        spec = builtin.TOOLS.get(body.tool_name)
        risk = spec.risk if spec else 100
        resource = orch.builtin_tool_schema(body.tool_name).get("name", "")
        d = policy_engine.evaluate(p.id, p.version, tool_name=body.tool_name,
                                   action_type="tool_call", risk=risk)
        return {"decision": d.to_dict(), "tool_registered": spec is not None, "tool_risk": risk}


@router.get("/policies/{policy_id}/conflicts", tags=["policy"])
def policy_conflicts(policy_id: str, principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
    _authorize_policy(principal, policy_id, "viewer")
    with session_scope() as s:
        p = s.get(Policy, policy_id)
        policy_engine.load(p.id, p.version, p.document)
        return {"conflicts": policy_engine.explain_conflicts(p.id, p.version)}


# --------------------------------------------------------------- scenarios

@router.get("/scenarios", tags=["scenarios"])
def list_scenarios(category: str | None = None, principal: Principal = Depends(require_viewer)) -> list[dict[str, Any]]:
    with session_scope() as s:
        q = select(Scenario)
        if category:
            q = q.where(Scenario.category == category)
        rows = s.scalars(q).all()
        return [{"key": r.key, "category": r.category, "title": r.title, "description": r.description,
                 "risk": r.risk, "source": r.source, "template": r.template} for r in rows]


@router.get("/scenarios/categories", tags=["scenarios"])
def scenario_categories(principal: Principal = Depends(require_viewer)) -> dict[str, str]:
    return CATEGORIES


@router.post("/scenarios", tags=["scenarios"])
def create_custom_scenario(body: S.CustomScenarioRequest, principal: Principal = Depends(require_researcher)) -> dict[str, Any]:
    tpl = body.template
    if "messages" not in tpl or "expected" not in tpl:
        raise HTTPException(400, "template requires 'messages' and 'expected' (with outcome)")
    if tpl.get("expected", {}).get("outcome") not in ("refuse", "comply"):
        raise HTTPException(400, "expected.outcome must be 'refuse' or 'comply'")
    with session_scope() as s:
        if s.get(Scenario, body.key):
            raise HTTPException(409, "scenario key exists")
        scen = Scenario(key=body.key, category=body.category, title=body.title,
                        description=body.description, template=tpl, risk=body.risk, source="custom")
        s.add(scen)
        authsvc.audit(principal.email, "scenario.created", "scenario", body.key, session=s)
        return {"key": scen.key}


# ------------------------------------------------------------- experiments

@router.get("/experiments", tags=["experiments"])
def list_experiments(principal: Principal = Depends(require_viewer)) -> list[dict[str, Any]]:
    accessible = _accessible_project_ids(principal)
    with session_scope() as s:
        q = select(Experiment).order_by(Experiment.created_at.desc())
        if accessible != "all":
            if not accessible:
                return []
            q = q.where(Experiment.project_id.in_(accessible))
        rows = s.scalars(q).all()
        return [_exp_dict(e) for e in rows]


def _exp_dict(e: Experiment) -> dict[str, Any]:
    return {"id": e.id, "project_id": e.project_id, "target_id": e.target_id, "policy_id": e.policy_id,
            "title": e.title, "status": e.status, "scenario_keys": e.scenario_keys,
            "stats": e.stats, "started_at": str(e.started_at or ""), "finished_at": str(e.finished_at or ""),
            "config": e.config, "adapter_version": e.adapter_version, "policy_version": e.policy_version,
            "target_model": e.target_model, "error": e.error}


@router.post("/experiments", tags=["experiments"])
def create_experiment(body: S.ExperimentRequest, principal: Principal = Depends(require_researcher)) -> dict[str, Any]:
    settings = get_settings()
    _project_role_or_404(principal, body.project_id, "researcher")
    _validate_experiment_resources(body.project_id, body.target_id, body.policy_id)
    cfg = body.config or {}
    cfg.setdefault("replays", settings.case_replays)
    if len(body.scenario_keys) * int(cfg.get("replays", 1)) > settings.max_cases_per_experiment:
        raise HTTPException(400, f"cases exceed limit ({settings.max_cases_per_experiment})")
    if not isinstance(cfg.get("replays", 1), int) or cfg.get("replays", 1) < 1 or cfg.get("replays", 1) > 10:
        raise HTTPException(400, "config.replays must be an integer between 1 and 10")
    try:
        result = orch.create_experiment(
            project_id=body.project_id, target_id=body.target_id, policy_id=body.policy_id,
            scenario_keys=body.scenario_keys, title=body.title, authorization=body.authorization,
            config=cfg, created_by=principal.id)
    except RuntimeError as exc:
        raise HTTPException(423, str(exc))
    except PermissionError as exc:
        raise HTTPException(403, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    authsvc.audit(principal.email, "experiment.created", "experiment", result["id"],
                  detail={"scenarios": body.scenario_keys})
    return result


@router.post("/experiments/{experiment_id}/start", tags=["experiments"])
async def start_experiment(experiment_id: str, principal: Principal = Depends(require_researcher)) -> dict[str, Any]:
    if orch.emergency_stop_active():
        raise HTTPException(423, "emergency stop active")
    _authorize_experiment(principal, experiment_id, "researcher")
    with session_scope() as s:
        exp = s.get(Experiment, experiment_id)
        if not exp:
            raise HTTPException(404, "experiment not found")
    task = asyncio.create_task(orch.run_experiment(experiment_id))
    authsvc.audit(principal.email, "experiment.started", "experiment", experiment_id)
    return {"id": experiment_id, "started": True, "task": id(task)}


@router.get("/experiments/{experiment_id}", tags=["experiments"])
def get_experiment(experiment_id: str, principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
    _authorize_experiment(principal, experiment_id, "viewer")
    with session_scope() as s:
        exp = s.get(Experiment, experiment_id)
        cases = s.scalars(select(Case).where(Case.experiment_id == experiment_id).order_by(Case.seq)).all()
        d = _exp_dict(exp)
        d["cases"] = [{"id": c.id, "seq": c.seq, "scenario_key": c.scenario_key, "replay": c.replay,
                       "status": c.status, "outcome": c.outcome, "trace_id": c.trace_id,
                       "finding_id": c.finding_id} for c in cases]
        return d


@router.post("/experiments/{experiment_id}/cancel", tags=["experiments"])
def cancel_experiment(experiment_id: str, principal: Principal = Depends(require_researcher)) -> dict[str, Any]:
    _authorize_experiment(principal, experiment_id, "researcher")
    try:
        cancelled = orch.cancel_experiment(experiment_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    authsvc.audit(principal.email, "experiment.cancelled", "experiment", experiment_id)
    return {"id": experiment_id, "cancelled": cancelled}


@router.get("/experiments/{experiment_id}/events", tags=["experiments"])
def experiment_events(experiment_id: str, principal: Principal = Depends(require_viewer),
                      limit: int = Query(500, le=5000)) -> list[dict[str, Any]]:
    _authorize_experiment(principal, experiment_id, "viewer")
    with session_scope() as s:
        rows = s.scalars(select(EventRecord).where(EventRecord.experiment_id == experiment_id)
                         .order_by(EventRecord.seq).limit(limit)).all()
        return [event_to_dict(e) for e in rows]


@router.get("/experiments/{experiment_id}/trace-analysis", tags=["experiments"])
def trace_analysis(experiment_id: str, principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
    _authorize_experiment(principal, experiment_id, "viewer")
    with session_scope() as s:
        rows = s.scalars(select(EventRecord).where(EventRecord.experiment_id == experiment_id)
                         .order_by(EventRecord.seq)).all()
        return rt.trace_analysis_report([event_to_dict(e) for e in rows])


# ---------------------------------------------------------------- approvals

@router.get("/approvals/pending", tags=["approvals"])
def pending_approvals(principal: Principal = Depends(require_viewer)) -> list[dict[str, Any]]:
    """Pending approvals scoped to experiments in accessible projects."""
    accessible = _accessible_project_ids(principal)
    with session_scope() as s:
        rows = s.scalars(select(Approval).where(Approval.status == "pending")).all()
        out = []
        for a in rows:
            if accessible != "all":
                e = s.get(Experiment, a.experiment_id)
                if not e or e.project_id not in accessible:
                    continue
            out.append({"id": a.id, "experiment_id": a.experiment_id, "case_id": a.case_id,
                        "tool_name": a.tool_name, "arguments": a.arguments, "reason": a.reason,
                        "requested_at": str(a.created_at)})
        return out


@router.post("/approvals/{approval_id}/decide", tags=["approvals"])
def decide_approval(approval_id: str, body: S.ApproveRequest,
                    principal: Principal = Depends(require_admin)) -> dict[str, Any]:
    """Only admins may approve consequential actions (human approval gate)."""
    with session_scope() as s:
        a = s.get(Approval, approval_id)
        if not a:
            raise HTTPException(404, "approval not found")
        if a.status != "pending":
            raise HTTPException(409, f"approval already '{a.status}'")
        e = s.get(Experiment, a.experiment_id)
        if e and _accessible_project_ids(principal) != "all":
            _project_role_or_404(principal, e.project_id, "admin")
        a.status = body.decision
        a.decided_by = principal.email
        a.decided_at = utcnow()
        a.reason = body.reason
        record_event(s, experiment_id=a.experiment_id, case_id=a.case_id,
                     type_="approval.decided", actor=principal.email,
                     payload={"approval_id": a.id, "decision": body.decision, "reason": body.reason})
        if body.decision == "approved":
            gw = _gateway_for_experiment(s, a.experiment_id)
            res = gw.execute_approved(s, a, a.experiment_id, a.case_id, None)
            authsvc.audit(principal.email, "approval.granted_executed", "approval", a.id, session=s,
                          detail={"tool": a.tool_name, "executed": res.executed})
            return {"approval_id": a.id, "decision": "approved", "executed": res.to_dict()}
        authsvc.audit(principal.email, "approval.denied", "approval", a.id, {"tool": a.tool_name}, session=s)
        return {"approval_id": a.id, "decision": "denied"}


def _gateway_for_experiment(s, experiment_id: str) -> orch.ToolGateway:
    from app.policy.engine import policy_engine
    exp = s.get(Experiment, experiment_id)
    ensure_loaded(policy_engine, exp.policy_id, exp.policy_version, s)
    return orch.ToolGateway(policy_engine, exp.policy_id, exp.policy_version,
                            get_settings().sandbox_dir,
                            mode=exp.config.get("gateway_mode", "simulated"),
                            dry_run=bool(exp.config.get("dry_run")))


def ensure_loaded(engine, policy_id: str, version: int, s) -> None:
    if (policy_id, version) in engine._cache:
        return
    p = s.get(Policy, policy_id)
    engine.load(policy_id, version, p.document)


# ---------------------------------------------------------------- findings

@router.get("/findings", tags=["findings"])
def list_findings(experiment_id: str | None = None, status: str | None = None,
                  severity: str | None = None, principal: Principal = Depends(require_viewer)) -> list[dict[str, Any]]:
    accessible = _accessible_project_ids(principal)
    with session_scope() as s:
        q = select(Finding)
        if experiment_id:
            _authorize_experiment(principal, experiment_id, "viewer")
            q = q.where(Finding.experiment_id == experiment_id)
        elif accessible != "all":
            exp_ids = s.scalars(select(Experiment.id).where(
                Experiment.project_id.in_(accessible))).all() if accessible else []
            q = q.where(Finding.experiment_id.in_(exp_ids)) if exp_ids else q.where(False)
        if status:
            q = q.where(Finding.status == status)
        if severity:
            q = q.where(Finding.severity == severity)
        rows = s.scalars(q.order_by(Finding.created_at.desc())).all()
        return [_finding_dict(f) for f in rows]


def _finding_dict(f: Finding) -> dict[str, Any]:
    return {"id": f.id, "experiment_id": f.experiment_id, "case_id": f.case_id,
            "target_id": f.target_id, "title": f.title, "category": f.category,
            "vuln_class": f.vuln_class, "severity": f.severity, "confidence": f.confidence,
            "status": f.status, "expected": f.expected, "observed": f.observed,
            "preconditions": f.preconditions, "impact": f.impact, "likelihood": f.likelihood,
            "limitations": f.limitations, "remediation": f.remediation,
            "evidence_event_ids": f.evidence_event_ids, "reproduction": f.reproduction,
            "failure_layer": f.failure_layer, "reproducible": f.reproducible,
            "created_at": str(f.created_at), "updated_at": str(f.updated_at)}


@router.get("/findings/{finding_id}", tags=["findings"])
def get_finding(finding_id: str, principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
    _authorize_finding(principal, finding_id)
    with session_scope() as s:
        f = s.get(Finding, finding_id)
        reg = s.scalar(select(Regression).where(Regression.finding_id == f.id))
        d = _finding_dict(f)
        d["regression_scenario_key"] = reg.scenario_key if reg else None
        return d


@router.post("/findings/{finding_id}/verify", tags=["findings"])
def verify(finding_id: str, principal: Principal = Depends(require_researcher)) -> dict[str, Any]:
    _authorize_finding(principal, finding_id)
    with session_scope() as s:
        f = s.get(Finding, finding_id)
        verify_finding(s, f)
        record_event(s, experiment_id=f.experiment_id, type_="finding.verified",
                     actor=principal.email, payload={"finding_id": f.id, "status": f.status})
        authsvc.audit(principal.email, "finding.verified", "finding", f.id, {"status": f.status}, session=s)
        return _finding_dict(f)


# ---------------------------------------------------------------- red team

@router.post("/redteam/variations", tags=["redteam"])
def create_variations(body: S.RedTeamRequest, principal: Principal = Depends(require_researcher)) -> dict[str, Any]:
    with session_scope() as s:
        keys = rt.register_variations(s, body.base_scenario_keys, body.variations_per_base, principal.id)
    authsvc.audit(principal.email, "redteam.variations_created", "scenario", "", {"count": len(keys)})
    return {"variation_keys": keys, "note": "variations inherit the base scenario's expected contract; scope unchanged"}


@router.post("/redteam/remediation", tags=["redteam"])
def remediation(experiment_id: str, principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
    _authorize_experiment(principal, experiment_id, "viewer")
    with session_scope() as s:
        rows = s.scalars(select(Finding).where(Finding.experiment_id == experiment_id)).all()
        plan = rt.remediation_plan([_finding_dict(f) for f in rows])
    return {"experiment_id": experiment_id, "plan": plan}


# --------------------------------------------------------------- benchmarks

@router.get("/benchmarks/suites", tags=["benchmarks"])
def benchmark_suites(principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
    return {"suites": bench.SUITES, "dynamic": ["regression-pack"]}


@router.post("/benchmarks/run", tags=["benchmarks"])
async def run_benchmark(body: S.BenchmarkRequest, principal: Principal = Depends(require_researcher)) -> dict[str, Any]:
    _project_role_or_404(principal, body.project_id, "researcher")
    _validate_experiment_resources(body.project_id, body.target_id, body.policy_id)
    try:
        with session_scope() as s:
            scenario_keys = bench.resolve_suite_scenarios(s, body.suite_key)
        if not scenario_keys:
            raise HTTPException(400, f"suite '{body.suite_key}' has no scenarios")
        result = orch.create_experiment(
            project_id=body.project_id, target_id=body.target_id, policy_id=body.policy_id,
            scenario_keys=scenario_keys, title=f"Benchmark suite '{body.suite_key}'",
            authorization=body.authorization, config=body.config | {"replays": 1},
            created_by=principal.id)
    except PermissionError as exc:
        raise HTTPException(403, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    run = BenchmarkRun(id=new_id("bmk"), suite_key=body.suite_key, target_id=body.target_id,
                       project_id=body.project_id, policy_id=body.policy_id,
                       config=body.config, status="running", experiment_id=result["id"],
                       started_at=utcnow())
    with session_scope() as s:
        s.add(run)
        s.flush()
        run_id = run.id

    await orch.run_experiment(result["id"])

    with session_scope() as s:
        cases = s.scalars(select(Case).where(Case.experiment_id == result["id"])).all()
        metrics = bench.compute_metrics(cases)
        run_row = s.get(BenchmarkRun, run_id)
        # GX-004 fix: honest terminal states. Provider failures are NOT a
        # successful evaluation.
        n_cases = len(cases)
        n_infra = sum(1 for c in cases if c.status == "infra_error")
        n_evaluated = n_cases - n_infra
        if n_evaluated == 0 and n_cases > 0:
            run_row.status = "failed"
        elif n_infra > 0:
            run_row.status = "completed_with_failures"
        else:
            run_row.status = "completed"
        run_row.metrics = metrics
        run_row.finished_at = utcnow()
        authsvc.audit(principal.email, "benchmark.completed", "benchmark", run_id, session=s,
                      detail={"suite": body.suite_key, "status": run_row.status,
                              "infra_errors": n_infra})
        return {"benchmark_id": run_id, "experiment_id": result["id"], "status": run_row.status,
                "infra_errors": n_infra, "cases": n_cases, "metrics": metrics}


@router.get("/benchmarks", tags=["benchmarks"])
def list_benchmarks(principal: Principal = Depends(require_viewer)) -> list[dict[str, Any]]:
    accessible = _accessible_project_ids(principal)
    with session_scope() as s:
        q = select(BenchmarkRun).order_by(BenchmarkRun.created_at.desc())
        if accessible != "all":
            if not accessible:
                return []
            q = q.where(BenchmarkRun.project_id.in_(accessible))
        rows = s.scalars(q).all()
        return [{"id": b.id, "suite_key": b.suite_key, "target_id": b.target_id,
                 "status": b.status, "metrics": b.metrics, "experiment_id": b.experiment_id,
                 "started_at": str(b.started_at or ""), "finished_at": str(b.finished_at or "")} for b in rows]


# ------------------------------------------------------------------- events

@router.get("/events", tags=["observability"])
def search_events(experiment_id: str | None = None, type_: str | None = Query(None, alias="type"),
                  level: str | None = None, limit: int = Query(200, le=2000),
                  principal: Principal = Depends(require_viewer)) -> list[dict[str, Any]]:
    accessible = _accessible_project_ids(principal)
    with session_scope() as s:
        q = select(EventRecord).order_by(EventRecord.created_at.desc()).limit(limit)
        if experiment_id:
            _authorize_experiment(principal, experiment_id, "viewer")
            q = q.where(EventRecord.experiment_id == experiment_id)
        elif accessible != "all":
            exp_ids = s.scalars(select(Experiment.id).where(
                Experiment.project_id.in_(accessible))).all() if accessible else []
            q = q.where(EventRecord.experiment_id.in_(exp_ids)) if exp_ids else q.where(False)
        if type_:
            q = q.where(EventRecord.type == type_)
        if level:
            q = q.where(EventRecord.level == level)
        rows = s.scalars(q).all()
        return [event_to_dict(e) for e in rows]


@router.get("/events/stream", tags=["observability"])
async def event_stream(experiment_id: str | None = None,
                       principal: Principal = Depends(require_viewer)) -> StreamingResponse:
    async def gen():
        q = await bus.subscribe(experiment_id)
        try:
            yield ": connected\n\n"
            while True:
                ev = await q.get()
                yield f"data: {json.dumps(redact_obj(ev), default=str)}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            await bus.unsubscribe(q, experiment_id)
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# -------------------------------------------------------------------- admin

@router.post("/admin/emergency-stop", tags=["admin"])
def emergency_stop(body: dict[str, Any], principal: Principal = Depends(require_admin)) -> dict[str, Any]:
    active = bool(body.get("active", True))
    orch.emergency_stop(active)
    authsvc.audit(principal.email, "admin.emergency_stop", "system", "", {"active": active})
    return {"emergency_stop": active}


@router.get("/admin/audit", tags=["admin"])
def audit_log(limit: int = Query(200, le=2000), principal: Principal = Depends(require_admin)) -> list[dict[str, Any]]:
    from app.models import AuditEvent
    with session_scope() as s:
        rows = s.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)).all()
        return [{"id": a.id, "actor": a.actor, "action": a.action, "object_type": a.object_type,
                 "object_id": a.object_id, "detail": a.detail, "created_at": str(a.created_at)} for a in rows]


@router.get("/admin/stats", tags=["admin"])
def stats(principal: Principal = Depends(require_admin)) -> dict[str, Any]:
    """Global platform statistics. ADMIN ONLY (GX-008 fix). Scoped aggregates
    for ordinary users live at /dashboard/summary."""
    with session_scope() as s:
        return {
            "users": s.query(authsvc.User).count(),
            "targets": s.query(Target).count(),
            "targets_operational": s.query(Target).filter(Target.status == "operational").count(),
            "experiments": s.query(Experiment).count(),
            "experiments_running": len(orch.EXPERIMENT_TASKS),
            "findings_confirmed": s.query(Finding).filter(
                Finding.status.in_(["confirmed", "remediation_proposed", "regression_tested", "closed"])).count(),
            "findings_total": s.query(Finding).count(),
            "findings_by_severity": _count_by(s, Finding, Finding.severity),
            "findings_by_status": _count_by(s, Finding, Finding.status),
            "benchmarks": s.query(BenchmarkRun).count(),
            "approvals_pending": s.query(Approval).filter(Approval.status == "pending").count(),
            "emergency_stop": orch.emergency_stop_active(),
        }


@router.get("/dashboard/summary", tags=["admin"])
def dashboard_summary(principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
    """Scope-limited aggregates for signed-in users: only projects the caller
    can access are counted. No global counters, no user inventory."""
    accessible = _accessible_project_ids(principal)
    with session_scope() as s:
        q_exp = s.query(Experiment)
        q_tgt = s.query(Target)
        if accessible != "all":
            if not accessible:
                return {"projects": 0, "targets": 0, "targets_operational": 0, "experiments": 0,
                        "experiments_running": 0, "findings_total": 0, "findings_confirmed": 0,
                        "findings_by_severity": {}, "benchmarks": 0,
                        "approvals_pending": 0, "emergency_stop": orch.emergency_stop_active()}
            q_exp = q_exp.filter(Experiment.project_id.in_(accessible))
            q_tgt = q_tgt.filter(Target.project_id.in_(accessible))
        exp_ids = [e.id for e in q_exp.with_entities(Experiment.id).all()]
        q_f = s.query(Finding)
        if accessible != "all":
            q_f = q_f.filter(Finding.experiment_id.in_(exp_ids)) if exp_ids else q_f.filter(False)
        return {
            "projects": len(accessible) if accessible != "all" else s.query(Project).count(),
            "targets": q_tgt.count(),
            "targets_operational": q_tgt.filter(Target.status == "operational").count(),
            "experiments": q_exp.count(),
            "experiments_running": len(orch.EXPERIMENT_TASKS),
            "findings_total": q_f.count(),
            "findings_confirmed": q_f.filter(
                Finding.status.in_(["confirmed", "remediation_proposed", "regression_tested", "closed"])).count(),
            "findings_by_severity": _count_by_query(q_f, Finding.severity),
            "benchmarks": s.query(BenchmarkRun).filter(BenchmarkRun.project_id.in_(accessible)).count()
                          if accessible != "all" else s.query(BenchmarkRun).count(),
            "approvals_pending": s.query(Approval).filter(Approval.status == "pending").count()
                                  if accessible == "all" else 0,  # approvals are admin-surfaced
            "emergency_stop": orch.emergency_stop_active(),
        }


def _count_by_query(q, col) -> dict[str, int]:
    from collections import Counter
    return dict(Counter(x[0] for x in q.with_entities(col).all()))


# ------------------------------------------------------------- user admin

@router.get("/admin/users", tags=["admin"])
def list_users(principal: Principal = Depends(require_admin)) -> list[dict[str, Any]]:
    with session_scope() as s:
        rows = s.scalars(select(authsvc.User)).all()
        return [{"id": u.id, "email": u.email, "role": u.role, "disabled": u.disabled,
                 "email_verified": u.email_verified, "created_at": str(u.created_at)} for u in rows]


def _active_admin_count(s) -> int:
    return s.query(authsvc.User).filter(authsvc.User.role == "admin",
                                        authsvc.User.disabled == False).count()  # noqa: E712


def _guard_not_last_admin(s, user_id: str, principal: Principal) -> None:
    """Phase 7: the last ACTIVE administrator cannot be demoted/disabled.

    Atomicity: on PostgreSQL a transaction-scoped advisory lock serializes
    concurrent role changes; on SQLite the single-writer commit serializes
    them. The count check and the update share the caller's transaction, so
    two concurrent demotions can never remove the final active admin.
    """
    from sqlalchemy import text as _text
    from app.db import _is_postgres
    if _is_postgres():
        s.execute(_text(f"SELECT pg_advisory_xact_lock({736_251_003})"))
    target = s.get(authsvc.User, user_id)
    if not target or target.role != "admin" or target.disabled:
        return  # demoting a non-admin / already-disabled user is unconstrained
    if _active_admin_count(s) <= 1:
        # audit in a SEPARATE transaction: this one is about to roll back
        authsvc.audit(principal.email, "admin.last_admin_protected", "user", user_id,
                      {"action": "role_or_disable_change"})
        raise HTTPException(409, "cannot demote or disable the last active administrator")


@router.post("/admin/users/{user_id}/role", tags=["admin"])
def change_role(user_id: str, body: S.RoleChangeRequest,
                principal: Principal = Depends(require_admin)) -> dict[str, Any]:
    with session_scope() as s:
        u = s.get(authsvc.User, user_id)
        if not u:
            raise HTTPException(404, "user not found")
        _guard_not_last_admin(s, user_id, principal)
        old = u.role
        u.role = body.role
    revoked = 0
    if body.revoke_credentials:
        revoked = authsvc.revoke_user_credentials(user_id)
    authsvc.audit(principal.email, "user.role_changed", "user", user_id,
                  {"old_role": old, "new_role": body.role, "sessions_revoked": revoked})
    return {"id": user_id, "role": body.role, "sessions_revoked": revoked}


@router.post("/admin/users/{user_id}/disable", tags=["admin"])
def disable_user(user_id: str, body: S.DisableRequest,
                 principal: Principal = Depends(require_admin)) -> dict[str, Any]:
    if user_id == principal.id and body.disabled:
        raise HTTPException(409, "cannot disable your own account; ask another administrator")
    with session_scope() as s:
        u = s.get(authsvc.User, user_id)
        if not u:
            raise HTTPException(404, "user not found")
        if body.disabled:
            _guard_not_last_admin(s, user_id, principal)
        u.disabled = body.disabled
    revoked = 0
    if body.disabled:
        revoked = authsvc.revoke_user_credentials(user_id)
    authsvc.audit(principal.email, "user.disable_changed", "user", user_id,
                  {"disabled": body.disabled, "sessions_revoked": revoked})
    return {"id": user_id, "disabled": body.disabled, "sessions_revoked": revoked}


@router.post("/admin/users/{user_id}/revoke-credentials", tags=["admin"])
def revoke_user_credentials_route(user_id: str, principal: Principal = Depends(require_admin)) -> dict[str, Any]:
    with session_scope() as s:
        u = s.get(authsvc.User, user_id)
        if not u:
            raise HTTPException(404, "user not found")
    n = authsvc.revoke_user_credentials(user_id)
    authsvc.audit(principal.email, "user.credentials_revoked", "user", user_id, {"revoked": n})
    return {"ok": True, "revoked": n}


def _count_by(s, model, col) -> dict[str, int]:
    from collections import Counter
    return dict(Counter(x[0] for x in s.query(col).all()))


@router.get("/admin/events/severity", tags=["admin"])
def enforcement_failures(principal: Principal = Depends(require_admin)) -> list[dict[str, Any]]:
    """Recent enforcement events are cross-project; admin-only (Part 4.3)."""
    with session_scope() as s:
        rows = s.scalars(select(EventRecord).where(
            EventRecord.type.in_(["tool.blocked", "tool.executed", "approval.requested", "finding.discovered"]))
            .order_by(EventRecord.created_at.desc()).limit(100)).all()
        return [event_to_dict(e) for e in rows]
