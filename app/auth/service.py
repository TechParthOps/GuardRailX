"""Authentication, RBAC, sessions/API keys, and audit logging.

Security model (fixes GX-001, GX-007):
  * A credential's `role` is a privilege CEILING fixed at issuance.
  * The EFFECTIVE role of a request = min(user's current role, ceiling).
    Role demotion and account disablement take effect immediately.
  * API keys carry explicit `scopes`: ["*"] or ["project:<id>", ...]. A child
    key can never exceed its creator's effective role or scope set.
  * Password hashing is Argon2id; legacy PBKDF2 hashes verify and are
    transparently upgraded on next successful login.
  * Only hashes are stored; tokens are compared via HMAC-SHA256 with a
    server-side secret; verification is constant-time.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from fastapi import Depends, HTTPException, Request
from sqlalchemy import select, update

from app.config import get_settings
from app.db import session_scope
from app.models import AuditEvent, AuthToken, Project, ProjectMember, User, UserToken, new_id

_ph = PasswordHasher()  # argon2id defaults (64MB, t=3, p=4)
PBKDF2_ITERATIONS = 240_000
ROLE_RANK = {"viewer": 0, "researcher": 1, "admin": 2}
VALID_ROLES = tuple(ROLE_RANK)
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")


def normalize_email(email: str) -> str:
    e = (email or "").strip().lower()
    if not EMAIL_RE.match(e) or len(e) > 255:
        raise ValueError("invalid email address")
    return e


# ------------------------------------------------------------ passwords

def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verification for both Argon2id and legacy PBKDF2 hashes."""
    if not stored or not isinstance(stored, str):
        return False
    if stored.startswith("pbkdf2$"):
        try:
            _, iters, salt_hex, dk_hex = stored.split("$")
            dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iters))
            return hmac.compare_digest(dk.hex(), dk_hex)
        except (ValueError, TypeError):
            return False
    try:
        return _ph.verify(stored, password)
    except (VerifyMismatchError, InvalidHashError, ValueError):
        return False


def needs_rehash(stored: str) -> bool:
    return bool(stored) and stored.startswith("pbkdf2$") or (
        stored.startswith("$argon2") and _ph.check_needs_rehash(stored))


def password_policy_error(password: str) -> str | None:
    """Signup/change policy; returns a human-readable reason or None."""
    if len(password) < 12:
        return "password must be at least 12 characters"
    if len(password) > 256:
        return "password too long"
    if not re.search(r"[a-z]", password) or not re.search(r"[A-Z]", password) \
            or not re.search(r"[0-9]", password):
        return "password must include upper case, lower case, and a digit"
    return None


# ---------------------------------------------------------------- tokens

def _hash_token(token: str) -> str:
    secret = get_settings().get_or_create_secret()
    return hashlib.sha256((secret + token).encode()).hexdigest()


def create_user(email: str, password: str, role: str = "viewer",
                email_verified: bool = False) -> User:
    with session_scope() as s:
        e = normalize_email(email)
        existing = s.scalar(select(User).where(User.email == e))
        if existing:
            raise ValueError("user exists")
        u = User(id=new_id("usr"), email=e, password_hash=hash_password(password),
                 role=role, email_verified=email_verified)
        s.add(u)
        return u


def _new_auth_token(s, *, user: User, kind: str, token: str, role: str,
                    scopes: list[str], name: str, ttl: timedelta) -> AuthToken:
    at = AuthToken(
        id=new_id("ses" if kind == "session" else "key"),
        user_id=user.id, kind=kind, token_hash=_hash_token(token),
        prefix=token[:7], name=name, role=role, scopes=scopes,
        expires_at=datetime.now(timezone.utc) + ttl,
    )
    s.add(at)
    return at


def authenticate(email: str, password: str) -> tuple[User | None, str | None]:
    """Returns (user, bearer_token). Transparently upgrades legacy hashes."""
    try:
        e = normalize_email(email)
    except ValueError:
        return None, None
    with session_scope() as s:
        u = s.scalar(select(User).where(User.email == e, User.disabled == False))  # noqa: E712
        if not u or not verify_password(password, u.password_hash):
            return None, None
        if needs_rehash(u.password_hash):
            u.password_hash = hash_password(password)
        token = secrets.token_urlsafe(32)
        _new_auth_token(s, user=u, kind="session", token=token, role=u.role,
                        scopes=["*"], name="session",
                        ttl=timedelta(minutes=get_settings().session_ttl_minutes))
        return u, token


def create_api_key(creator: "Principal", name: str, role: str | None = None,
                   scopes: list[str] | None = None) -> tuple[str, AuthToken]:
    """Mint a key that can NEVER exceed the creator's effective privileges.

    GX-001 fix: the default role is the creator's EFFECTIVE role (not the
    account's stored role), and any request above the effective ceiling or
    outside the creator's scopes is rejected and audited.
    """
    requested_role = role or creator.effective_role
    if ROLE_RANK.get(requested_role, -1) > ROLE_RANK.get(creator.effective_role, -1):
        audit(creator.email, "auth.key_escalation_blocked", "api_key", "",
              {"requested_role": requested_role, "effective_role": creator.effective_role})
        raise PermissionError("cannot create a credential above your effective privileges")
    requested_scopes = scopes if scopes is not None else list(creator.scopes)
    if not _scopes_subset(requested_scopes, creator.scopes):
        audit(creator.email, "auth.key_scope_escalation_blocked", "api_key", "",
              {"requested_scopes": requested_scopes, "creator_scopes": creator.scopes})
        raise PermissionError("cannot create a credential with scopes beyond your own")
    token = "gx_" + secrets.token_urlsafe(32)
    with session_scope() as s:
        u = s.get(User, creator.id)
        if not u or u.disabled:
            raise PermissionError("creator account is disabled")
        at = _new_auth_token(s, user=u, kind="api_key", token=token,
                             role=requested_role, scopes=requested_scopes,
                             name=name[:120],
                             ttl=timedelta(days=get_settings().api_key_ttl_days))
        s.flush()
        audit(creator.email, "api_key.created", "api_key", at.id,
              {"name": name[:120], "role": requested_role, "scopes": requested_scopes},
              session=s)
        return token, at


def _scopes_subset(child: list[str], parent: list[str]) -> bool:
    if "*" in parent:
        return True
    if "*" in child:
        return False
    return set(child) <= set(parent)


def issue_user_token(user_id: str, kind: str, ttl_minutes: int) -> str:
    """Single-use account token (verify/reset); hash stored, raw shown once."""
    raw = secrets.token_urlsafe(32)
    with session_scope() as s:
        s.add(UserToken(id=new_id("utk"), user_id=user_id, kind=kind,
                        token_hash=_hash_token(raw),
                        expires_at=datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)))
    return raw


def consume_user_token(raw: str, kind: str) -> str | None:
    """Single-use consumption; returns user_id or None. Constant-time hash lookup."""
    th = _hash_token(raw)
    with session_scope() as s:
        rows = s.scalars(select(UserToken).where(UserToken.token_hash == th,
                                                 UserToken.kind == kind)).all()
        now = datetime.now(timezone.utc)
        for t in rows:
            exp = t.expires_at if t.expires_at.tzinfo else t.expires_at.replace(tzinfo=timezone.utc)
            if t.used_at is None and exp > now:
                t.used_at = now
                return t.user_id
    return None


def resolve_token(token: str) -> tuple[User | None, AuthToken | None]:
    """Bearer token OR API key resolution; fails closed.

    Effective privileges are computed from the CURRENT user record, so role
    changes and disablement apply immediately to outstanding credentials.
    """
    if not token:
        return None, None
    th = _hash_token(token)
    with session_scope() as s:
        at = s.scalar(select(AuthToken).where(AuthToken.token_hash == th, AuthToken.revoked == False))  # noqa: E712
        if not at:
            return None, None
        expires = _aware(at.expires_at)
        if expires and expires < datetime.now(timezone.utc):
            return None, None
        u = s.get(User, at.user_id)
        if not u or u.disabled:
            return None, None
        # live ceiling: min(current account role, credential role)
        eff_rank = min(ROLE_RANK.get(u.role, -1), ROLE_RANK.get(at.role, -1))
        effective = next((r for r, v in ROLE_RANK.items() if v == eff_rank), "viewer")
        s.expunge(u)
        s.expunge(at)
        u._effective_role = effective  # type: ignore[attr-defined]
        return u, at


def revoke_user_credentials(user_id: str, except_token_id: str | None = None) -> int:
    """Revoke every session/API key of a user (password change, disablement, admin action)."""
    with session_scope() as s:
        q = update(AuthToken).where(AuthToken.user_id == user_id, AuthToken.revoked == False)  # noqa: E712
        if except_token_id:
            q = q.where(AuthToken.id != except_token_id)
        res = s.execute(q.values(revoked=True))
        return int(res.rowcount or 0)


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ------------------------------------------------------------ principal

class Principal:
    """Request-time authorization context. Roles are EFFECTIVE values."""

    def __init__(self, user: User, token: AuthToken, effective_role: str):
        self.user = user
        self.token = token
        self.role = effective_role
        self.scopes = list(token.scopes or ["*"])

    @property
    def id(self) -> str:
        return self.user.id

    @property
    def email(self) -> str:
        return self.user.email

    @property
    def effective_role(self) -> str:
        return self.role

    def scope_allows(self, project_id: str) -> bool:
        return "*" in self.scopes or f"project:{project_id}" in self.scopes


def require_role(minimum: str):
    async def dep(request: Request) -> Principal:
        auth = request.headers.get("authorization", "")
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        if not token:
            raise HTTPException(401, "missing bearer token")
        user, at = resolve_token(token)
        if not user:
            raise HTTPException(401, "invalid or expired token")
        effective = getattr(user, "_effective_role", at.role)
        if ROLE_RANK.get(effective, -1) < ROLE_RANK[minimum]:
            audit(user.email, "authz.denied", "endpoint", request.url.path,
                  {"required": minimum, "effective": effective})
            raise HTTPException(403, f"requires role '{minimum}'")
        return Principal(user, at, effective)
    return dep


require_viewer = require_role("viewer")
require_researcher = require_role("researcher")
require_admin = require_role("admin")


# --------------------------------------------------- project membership

def project_access(principal: Principal, project_id: str) -> str | None:
    """Return the principal's project-level role, or None (fail-closed).

    Grants, in order:
      * platform admin (wildcard scope) -> admin
      * explicit credential scope "project:<id>" -> access at the credential's
        effective role (an administrator deliberately minted that scope)
      * project ownership -> admin
      * explicit project membership -> the member's role
    """
    if not principal.scope_allows(project_id):
        return None
    if principal.role == "admin":
        return "admin"
    if f"project:{project_id}" in (principal.scopes or []):
        return principal.role if ROLE_RANK.get(principal.role, 0) <= ROLE_RANK["researcher"] \
            else "researcher"
    with session_scope() as s:
        p = s.get(Project, project_id)
        if not p:
            return None
        if p.owner_id == principal.id:
            return "admin"
        m = s.scalar(select(ProjectMember).where(ProjectMember.project_id == project_id,
                                                 ProjectMember.user_id == principal.id))
        return m.role if m else None


def require_project_access(minimum: str, param: str = "project_id"):
    """Dependency factory: resolves the project id from path/query/body."""
    def dep(principal: Principal, request: Request) -> tuple[Principal, str]:
        project_id = request.query_params.get(param) or ""
        if not project_id:
            raise HTTPException(400, f"missing {param}")
        role = project_access(principal, project_id)
        if role is None or ROLE_RANK.get(role, -1) < ROLE_RANK[minimum]:
            audit(principal.email, "authz.project_denied", "project", project_id,
                  {"required": minimum, "effective": principal.role})
            raise HTTPException(404, "resource not found")  # 404: no enumeration
        return principal, project_id
    return dep


# ----------------------------------------------------------------- audit

def audit(actor: str, action: str, object_type: str = "", object_id: str = "",
          detail: dict | None = None, session=None) -> None:
    """Record an audit event. Reuses the caller's session when provided
    (avoids nested SQLite write locks)."""
    from app.observability.redaction import redact_obj

    def _write(s):
        s.add(AuditEvent(
            id=new_id("aud"), actor=actor, action=action, object_type=object_type,
            object_id=object_id, detail=redact_obj(detail or {}),
        ))

    if session is not None:
        _write(session)
        return
    with session_scope() as s:
        _write(s)
