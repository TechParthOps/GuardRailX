"""Secure first-run administrator setup (GX-005 fix).

CLI:      python -m app.setup                       (interactive, first admin)
          python -m app.setup --reset-password      (operator credential reset)
Web API:  POST /api/v1/setup  {setup_token, email, password}
          - only until the first admin exists
          - requires GX_SETUP_TOKEN to be set and to match

Never writes credentials to disk. Every setup action is audit-logged.
"""
from __future__ import annotations

import argparse
import getpass
import secrets
import sys

from sqlalchemy import select

from app.auth import service as authsvc
from app.config import get_settings
from app.db import session_scope
from app.models import User, new_id


def _admin_count() -> int:
    with session_scope() as s:
        return len(s.scalars(select(User).where(User.role == "admin",
                                                User.disabled == False)).all())  # noqa: E712


def _setup_completed() -> bool:
    """Single definition of setup completion (Phase 6): an ACTIVE administrator
    exists. The status endpoint and the setup handler share this definition."""
    return _admin_count() > 0


def _create_admin(email: str, password: str, actor: str) -> User:
    policy = authsvc.password_policy_error(password)
    if policy:
        raise ValueError(policy)
    u = authsvc.create_user(email, password, role="admin", email_verified=True)
    authsvc.audit(actor, "admin.setup_created", "user", u.id, {"bootstrap": True})
    return u


def setup_from_token(token: str, email: str, password: str) -> User:
    """Web bootstrap path; consumed once, refused after setup completes.

    Atomic under concurrency (Phase 6): the admin-existence check and the
    insert happen inside one serialized transaction. PostgreSQL takes a
    transaction-scoped advisory lock; SQLite serializes on its single-writer
    lock; the check is re-executed inside the transaction either way.
    """
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import text as _text

    from app.db import _is_postgres
    from app.models import AuthToken, new_id

    settings = get_settings()
    expected = settings.setup_token
    if not expected or not secrets.compare_digest(token or "", expected):
        authsvc.audit("setup-api", "admin.setup_denied", "user", "", {"reason": "invalid token"})
        raise PermissionError("invalid or missing setup token")
    if _setup_completed():
        raise PermissionError("setup already completed")

    policy = authsvc.password_policy_error(password)
    if policy:
        raise ValueError(policy)
    try:
        norm_email = authsvc.normalize_email(email)
    except ValueError as exc:
        raise ValueError("invalid email address") from exc
    raw_password_hash = authsvc.hash_password(password)

    if not _is_postgres():
        return _setup_sqlite_atomic(norm_email, raw_password_hash)

    with session_scope() as s:
        s.execute(_text(f"SELECT pg_advisory_xact_lock({736_251_002})"))
        # re-check INSIDE the serialized transaction
        if s.scalar(select(User).where(User.role == "admin",
                                       User.disabled == False)) is not None:  # noqa: E712
            raise PermissionError("setup already completed")
        u = User(id=new_id("usr"), email=norm_email, password_hash=raw_password_hash,
                 role="admin", email_verified=True)
        s.add(u)
        s.flush()
        # one session for the new admin, minted in the same transaction
        token_value = secrets.token_urlsafe(32)
        s.add(AuthToken(
            id=new_id("ses"), user_id=u.id, kind="session",
            token_hash=authsvc._hash_token(token_value),
            prefix=token_value[:7], name="setup", role="admin", scopes=["*"],
            expires_at=datetime.now(timezone.utc) + timedelta(
                minutes=get_settings().session_ttl_minutes)))
        authsvc.audit("setup-api", "admin.setup_created", "user", u.id,
                      {"bootstrap": True}, session=s)
        u._setup_session_token = token_value  # type: ignore[attr-defined]
        return u


def _setup_sqlite_atomic(email: str, password_hash: str) -> User:
    """SQLite bootstrap with BEGIN IMMEDIATE: the existence check and insert
    run inside the database's single-writer lock, so concurrent requests
    serialize and at most one first administrator is created."""
    import time as _time
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import text as _text

    from app.db import engine

    now = datetime.now(timezone.utc)
    user_id = new_id("usr")
    token_value = secrets.token_urlsafe(32)
    token_id = new_id("ses")
    audit_id = new_id("aud")
    expires = now + timedelta(minutes=get_settings().session_ttl_minutes)

    raw = engine.raw_connection()
    try:
        raw.execute("BEGIN IMMEDIATE")
        cur = raw.cursor()
        cur.execute("SELECT 1 FROM users WHERE role='admin' AND disabled=0 LIMIT 1")
        if cur.fetchone() is not None:
            raw.rollback()
            raise PermissionError("setup already completed")
        cur.execute(
            "INSERT INTO users (id, email, password_hash, role, disabled, email_verified, created_at)"
            " VALUES (?, ?, ?, 'admin', 0, 1, ?)",
            (user_id, email, password_hash, now.isoformat()))
        cur.execute(
            "INSERT INTO auth_tokens (id, user_id, kind, token_hash, prefix, name, role,"
            " scopes, expires_at, revoked, created_at)"
            " VALUES (?, ?, 'session', ?, ?, 'setup', 'admin', '[\"*\"]', ?, 0, ?)",
            (token_id, user_id, authsvc._hash_token(token_value), token_value[:7],
             expires.isoformat(), now.isoformat()))
        cur.execute(
            "INSERT INTO audit_events (id, actor, action, object_type, object_id, detail, created_at)"
            " VALUES (?, 'setup-api', 'admin.setup_created', 'user', ?, '{}', ?)",
            (audit_id, user_id, now.isoformat()))
        raw.commit()
    except PermissionError:
        raise
    except Exception as exc:
        try:
            raw.rollback()
        except Exception:
            pass
        raise RuntimeError(f"setup failed atomically: {exc}") from exc
    finally:
        raw.close()
    u = User(id=user_id, email=email, password_hash=password_hash, role="admin",
             email_verified=True)
    u._setup_session_token = token_value  # type: ignore[attr-defined]
    return u


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="GUARDRAIL-X administrator setup")
    parser.add_argument("--reset-password", action="store_true",
                        help="reset an existing account's password (operator action)")
    parser.add_argument("--email", default="")
    parser.add_argument("--password", default="", help="prefer interactive prompt over flag")
    args = parser.parse_args(argv)

    settings = get_settings()
    if settings.environment == "production" and settings.production_config_errors():
        print("Refusing setup: production configuration is incomplete:")
        for e in settings.production_config_errors():
            print(f"  - {e}")
        return 2

    if args.reset_password:
        email = args.email or input("Account email: ").strip()
        with session_scope() as s:
            u = s.scalar(select(User).where(User.email == email.strip().lower()))
            if not u:
                print("no such account")
                return 1
        pw = args.password or getpass.getpass("New password: ")
        policy = authsvc.password_policy_error(pw)
        if policy:
            print(policy)
            return 1
        with session_scope() as s:
            u2 = s.scalar(select(User).where(User.email == email.strip().lower()))
            u2.password_hash = authsvc.hash_password(pw)
        authsvc.revoke_user_credentials(u2.id)
        authsvc.audit("setup-cli", "admin.credential_reset", "user", u2.id,
                      {"sessions_revoked": True})
        print(f"password updated for {u2.email}; all sessions revoked")
        return 0

    if _admin_count() > 0:
        print("An administrator account already exists.")
        print("Use --reset-password to rotate credentials for an existing account.")
        return 1

    email = args.email or input("Administrator email: ").strip()
    pw = args.password or getpass.getpass("Administrator password: ")
    pw2 = args.password or getpass.getpass("Confirm password: ")
    if pw != pw2:
        print("passwords do not match")
        return 1
    try:
        u = _create_admin(email, pw, "setup-cli")
    except ValueError as exc:
        print(f"error: {exc}")
        return 1
    print(f"administrator created: {u.email}")
    print("Delete any legacy data/initial_admin_password.txt files from old deployments.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
