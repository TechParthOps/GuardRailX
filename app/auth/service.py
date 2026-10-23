"""Authentication, RBAC, sessions/API keys, and audit logging (Module M)."""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select

from app.config import get_settings
from app.db import session_scope
from app.models import AuditEvent, AuthToken, User, new_id

PBKDF2_ITERATIONS = 240_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iters, salt_hex, dk_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), dk_hex)
    except (ValueError, TypeError):
        return False


def _hash_token(token: str) -> str:
    secret = get_settings().get_or_create_secret()
    return hashlib.sha256((secret + token).encode()).hexdigest()


def create_user(email: str, password: str, role: str = "viewer") -> User:
    with session_scope() as s:
        existing = s.scalar(select(User).where(User.email == email))
        if existing:
            raise ValueError("user exists")
        u = User(id=new_id("usr"), email=email, password_hash=hash_password(password), role=role)
        s.add(u)
        return u


def authenticate(email: str, password: str) -> tuple[User | None, str | None]:
    """Returns (user, bearer_token)."""
    with session_scope() as s:
        u = s.scalar(select(User).where(User.email == email, User.disabled == False))  # noqa: E712
        if not u or not verify_password(password, u.password_hash):
            return None, None
        token = secrets.token_urlsafe(32)
        at = AuthToken(
            id=new_id("ses"), user_id=u.id, kind="session", token_hash=_hash_token(token),
            prefix=token[:6], name="session", role=u.role,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=get_settings().session_ttl_minutes),
        )
        s.add(at)
        return u, token


def create_api_key(user: User, name: str, role: str | None = None) -> tuple[str, AuthToken]:
    token = "gx_" + secrets.token_urlsafe(32)
    with session_scope() as s:
        at = AuthToken(
            id=new_id("key"), user_id=user.id, kind="api_key", token_hash=_hash_token(token),
            prefix=token[:7], name=name, role=role or user.role,
            expires_at=datetime.now(timezone.utc) + timedelta(days=get_settings().api_key_ttl_days),
        )
        s.add(at)
        s.flush()
        return token, at


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def resolve_token(token: str) -> tuple[User | None, AuthToken | None]:
    """Bearer token OR API key resolution; fails closed."""
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
        # detached copies for use outside the session
        s.expunge(u)
        s.expunge(at)
        return u, at


# ------------------------------------------------------------------ deps

class Principal:
    def __init__(self, user: User, token: AuthToken):
        self.user = user
        self.token = token
        self.role = token.role

    @property
    def id(self) -> str:
        return self.user.id

    @property
    def email(self) -> str:
        return self.user.email


ROLE_RANK = {"viewer": 0, "researcher": 1, "admin": 2}


def require_role(minimum: str):
    async def dep(request: Request) -> Principal:
        auth = request.headers.get("authorization", "")
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        if not token:
            raise HTTPException(401, "missing bearer token")
        user, at = resolve_token(token)
        if not user:
            raise HTTPException(401, "invalid or expired token")
        if ROLE_RANK.get(at.role, -1) < ROLE_RANK[minimum]:
            raise HTTPException(403, f"requires role '{minimum}'")
        return Principal(user, at)
    return dep


require_viewer = require_role("viewer")
require_researcher = require_role("researcher")
require_admin = require_role("admin")


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
