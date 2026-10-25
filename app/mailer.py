"""Account-token delivery (Phase 5).

Modes (GX_EMAIL_MODE):
  * console (default, development): tokens are printed to the server console
    ONLY — clearly labeled, never logged elsewhere, never returned via API.
  * smtp: real delivery via SMTP (TLS configurable). Required when
    GX_REQUIRE_EMAIL_VERIFICATION=true in production.

Token lifecycle guarantees live in app/auth/service.py:
  hashes only, high entropy, short expiry, single-use atomic consumption,
  rotation invalidates previous unused tokens, no token values in logs/audit.
"""
from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate

from app.config import get_settings

log = logging.getLogger("guardrailx.mailer")


class DeliveryError(Exception):
    """Delivery failed; the caller must not claim success to the user."""


def _smtp_send(to: str, subject: str, body: str) -> None:
    s = get_settings()
    timeout = float(s.smtp_timeout_seconds)
    host = s.smtp_host
    port = s.smtp_port
    if not host:
        raise DeliveryError("SMTP delivery is not configured (GX_SMTP_HOST missing)")
    if s.smtp_use_ssl:
        server = smtplib.SMTP_SSL(host, port, timeout=timeout)
    else:
        server = smtplib.SMTP(host, port, timeout=timeout)
    try:
        server.ehlo()
        if s.smtp_use_tls and not s.smtp_use_ssl:
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
        if s.smtp_username:
            server.login(s.smtp_username, s.smtp_password or "")
        msg = EmailMessage()
        msg["From"] = s.smtp_from
        msg["To"] = to
        msg["Subject"] = subject
        msg["Date"] = formatdate(localtime=False)
        msg.set_content(body)
        server.send_message(msg)
    finally:
        try:
            server.quit()
        except Exception:
            pass


def send_account_token(email: str, kind: str, raw_token: str) -> None:
    """Deliver a verification/reset token. NEVER log or return the token.

    Fail-closed (Priority 0): console delivery is permitted ONLY outside
    production. In production, a raw token must never reach stdout/logs —
    this holds even when email verification is disabled, because the
    password-reset workflow remains available by default.
    """
    s = get_settings()
    if s.environment == "production" and s.email_mode != "smtp":
        raise DeliveryError(
            "account-token delivery is not configured for production "
            "(GX_EMAIL_MODE must be 'smtp' with GX_SMTP_HOST set)")
    purpose = "email verification" if kind == "verify_email" else "password reset"
    minutes = s.verification_token_ttl_minutes if kind == "verify_email" \
        else s.reset_token_ttl_minutes
    body = (f"Your GUARDRAIL-X {purpose} token is:\n\n{raw_token}\n\n"
            f"This token is single-use and expires in {minutes} minutes. "
            "If you did not request this, ignore this message.")
    if s.email_mode == "smtp":
        try:
            _smtp_send(email, f"GUARDRAIL-X {purpose}", body)
        except Exception as exc:
            log.warning("account token delivery failed for %s (%s)", email, type(exc).__name__)
            raise DeliveryError(
                f"{purpose} token could not be delivered; try again later") from exc
        return
    # console mode (development/tests only): single labeled console line,
    # never structured logs, never returned via API
    print(f"[account-token delivery mode=console] {purpose} token for {email}: {raw_token}",
          flush=True)


def delivery_ready() -> tuple[bool, str]:
    """Whether the configured delivery path can actually deliver (startup check).

    Console mode is development-only: production requires verified SMTP
    configuration whenever ANY token workflow is enabled (signup verification
    or password reset — the latter is always on unless explicitly disabled).
    """
    s = get_settings()
    token_workflows_enabled = s.allow_password_reset or s.require_email_verification
    if s.email_mode == "smtp":
        if not s.smtp_host:
            return False, "GX_EMAIL_MODE=smtp but GX_SMTP_HOST is not configured"
        if not s.smtp_from or "@" not in s.smtp_from:
            return False, "GX_SMTP_FROM must be a valid sender address"
        return True, "smtp configured"
    if s.email_mode == "console":
        if s.environment == "production":
            if token_workflows_enabled:
                return False, ("console token delivery is not permitted in production; "
                               "configure SMTP (GX_EMAIL_MODE=smtp, GX_SMTP_HOST)")
            return True, "console mode (no token workflows enabled)"
        return True, "console mode (development)"
    return False, f"unknown GX_EMAIL_MODE '{s.email_mode}'"
