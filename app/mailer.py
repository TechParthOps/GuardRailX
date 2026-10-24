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
    """Deliver a verification/reset token. NEVER log or return the token."""
    s = get_settings()
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
    # console mode (development): single labeled console line, not structured logs
    print(f"[account-token delivery mode=console] {purpose} token for {email}: {raw_token}",
          flush=True)


def delivery_ready() -> tuple[bool, str]:
    """Whether the configured delivery path can actually deliver (startup check)."""
    s = get_settings()
    if s.email_mode == "smtp":
        if not s.smtp_host:
            return False, "GX_EMAIL_MODE=smtp but GX_SMTP_HOST is not configured"
        return True, "smtp configured"
    if s.email_mode == "console":
        if s.environment == "production" and s.require_email_verification:
            return False, ("console token delivery is not acceptable for production with "
                           "GX_REQUIRE_EMAIL_VERIFICATION=true; configure SMTP")
        return True, "console mode (development)"
    return False, f"unknown GX_EMAIL_MODE '{s.email_mode}'"
