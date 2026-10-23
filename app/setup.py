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
from app.models import User


def _admin_count() -> int:
    with session_scope() as s:
        return len(s.scalars(select(User).where(User.role == "admin")).all())


def _create_admin(email: str, password: str, actor: str) -> User:
    policy = authsvc.password_policy_error(password)
    if policy:
        raise ValueError(policy)
    u = authsvc.create_user(email, password, role="admin", email_verified=True)
    authsvc.audit(actor, "admin.setup_created", "user", u.id, {"bootstrap": True})
    return u


def setup_from_token(token: str, email: str, password: str) -> User:
    """Web bootstrap path; consumed once, refused after first admin exists."""
    settings = get_settings()
    expected = settings.setup_token
    if not expected or not secrets.compare_digest(token or "", expected):
        authsvc.audit("setup-api", "admin.setup_denied", "user", "", {"reason": "invalid token"})
        raise PermissionError("invalid or missing setup token")
    if _admin_count() > 0:
        raise PermissionError("setup already completed")
    u = _create_admin(email, password, "setup-api")
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
