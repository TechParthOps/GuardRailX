"""Priority 0 — production account-token delivery fail-closed tests."""
import pytest


def _prod_settings(monkeypatch, **overrides):
    from app.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "environment", "production")
    monkeypatch.setattr(s, "email_mode", "console")
    monkeypatch.setattr(s, "allow_password_reset", True)
    monkeypatch.setattr(s, "secret_key", "x" * 48)
    monkeypatch.setattr(s, "cors_origins", "https://prod.example.com")
    for k, v in overrides.items():
        monkeypatch.setattr(s, k, v)
    return s


# --------------------------------------------------- production fail-closed

def test_production_console_delivery_refused_at_send(monkeypatch, capsys):
    """Raw tokens must NEVER be printed in production, even when verification
    is disabled (password reset remains available)."""
    from app import mailer
    _prod_settings(monkeypatch)
    with pytest.raises(mailer.DeliveryError) as ei:
        mailer.send_account_token("user@prod.local", "reset_password", "RAW-TOKEN-xyz")
    assert "not configured for production" in str(ei.value)
    # the token must not have leaked to the console
    assert "RAW-TOKEN-xyz" not in capsys.readouterr().out


def test_production_console_startup_refused(monkeypatch):
    from app.config import get_settings
    from app.mailer import delivery_ready
    _prod_settings(monkeypatch)
    ok, why = delivery_ready()
    assert not ok and "SMTP" in why
    errors = get_settings().production_config_errors()
    assert any("account-token delivery misconfigured" in e for e in errors)


def test_production_with_smtp_configured_passes(monkeypatch):
    from app.config import get_settings
    from app.mailer import delivery_ready
    _prod_settings(monkeypatch, email_mode="smtp", smtp_host="smtp.prod.local",
                   smtp_from="gx@prod.local")
    ok, why = delivery_ready()
    assert ok, why
    assert get_settings().production_config_errors() == []


def test_production_smtp_without_host_fails_closed(monkeypatch):
    from app.config import get_settings
    from app.mailer import delivery_ready
    _prod_settings(monkeypatch, email_mode="smtp", smtp_host="")
    ok, why = delivery_ready()
    assert not ok and "GX_SMTP_HOST" in why


def test_production_smtp_without_sender_fails_closed(monkeypatch):
    from app.config import get_settings
    from app.mailer import delivery_ready
    _prod_settings(monkeypatch, email_mode="smtp", smtp_host="smtp.prod.local",
                   smtp_from="")
    ok, why = delivery_ready()
    assert not ok and "GX_SMTP_FROM" in why


def test_production_secret_key_strength(monkeypatch):
    from app.config import get_settings
    _prod_settings(monkeypatch, email_mode="smtp", smtp_host="h", smtp_from="a@b.c")
    s = get_settings()
    monkeypatch.setattr(s, "secret_key", "short")
    errors = s.production_config_errors()
    assert any("GX_SECRET_KEY is too short" in e for e in errors)
    monkeypatch.setattr(s, "secret_key", "x" * 48)
    assert not any("GX_SECRET_KEY" in e for e in s.production_config_errors())


# ------------------------------------------- reset workflow gating + safety

def test_reset_delivery_protected_even_when_verification_disabled(monkeypatch):
    """Verification OFF must not make console reset delivery production-ready."""
    from app import mailer
    from app.config import get_settings
    _prod_settings(monkeypatch, require_email_verification=False)
    assert get_settings().require_email_verification is False
    with pytest.raises(mailer.DeliveryError):
        mailer.send_account_token("u@prod.local", "reset_password", "TOKEN")


def test_reset_workflow_can_be_disabled_for_deliveryless_production(client, monkeypatch):
    """Operator escape hatch: disable the reset workflow explicitly."""
    from app.config import get_settings
    _prod_settings(monkeypatch, allow_password_reset=False,
                   require_email_verification=False)
    s = get_settings()
    assert s.production_config_errors() == []  # no token workflow -> console OK in prod
    # endpoints are gated
    r = client.post("/api/v1/auth/request-password-reset", json={"email": "x@y.local"})
    assert r.status_code == 200 and r.json()["ok"] is True  # generic (no enumeration)
    r2 = client.post("/api/v1/auth/reset-password",
                     json={"token": "whatever-token-value", "password": "Whatever-Pass-123"})
    assert r2.status_code == 403


def test_delivery_failure_does_not_leak_token(monkeypatch, smtp_server):
    from app import mailer
    from app.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "environment", "development")
    monkeypatch.setattr(s, "email_mode", "smtp")
    monkeypatch.setattr(s, "smtp_host", "127.0.0.1")
    monkeypatch.setattr(s, "smtp_port", 1)  # unreachable
    monkeypatch.setattr(s, "smtp_timeout_seconds", 1.0)
    with pytest.raises(mailer.DeliveryError) as ei:
        mailer.send_account_token("u@dev.local", "reset_password", "SECRET-TOKEN-42")
    assert "SECRET-TOKEN-42" not in str(ei.value)


def test_smtp_credentials_never_logged(monkeypatch, smtp_server, caplog):
    from app import mailer
    from app.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "environment", "development")
    monkeypatch.setattr(s, "email_mode", "smtp")
    monkeypatch.setattr(s, "smtp_host", "127.0.0.1")
    monkeypatch.setattr(s, "smtp_port", smtp_server.port)
    monkeypatch.setattr(s, "smtp_use_tls", False)
    # capture server does not support AUTH; the credential-leak assertion
    # is against logs/exceptions, so exercise the login path via a mock
    monkeypatch.setattr(s, "smtp_username", "gx-user")
    monkeypatch.setattr(s, "smtp_password", "gx-pass-123")
    monkeypatch.setattr(s, "smtp_timeout_seconds", 5.0)
    monkeypatch.setattr(mailer.smtplib, "SMTP", lambda *a, **k: _FakeSMTP(smtp_server.port))
    import logging
    with caplog.at_level(logging.DEBUG, logger="guardrailx.mailer"):
        mailer.send_account_token("u@dev.local", "verify_email", "TOKEN-CHECK")
    assert "gx-pass-123" not in caplog.text
    assert "TOKEN-CHECK" not in caplog.text


def test_development_console_delivery_works(monkeypatch, capsys):
    from app import mailer
    from app.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "environment", "development")
    monkeypatch.setattr(s, "email_mode", "console")
    mailer.send_account_token("dev@local", "verify_email", "DEV-TOKEN-9")
    out = capsys.readouterr().out
    assert "mode=console" in out and "DEV-TOKEN-9" in out


def test_unknown_email_mode_rejected(monkeypatch):
    from app.config import get_settings
    from app.mailer import delivery_ready
    _prod_settings(monkeypatch, email_mode="carrier-pigeon")
    ok, why = delivery_ready()
    assert not ok and "unknown GX_EMAIL_MODE" in why


def test_existing_reset_flow_still_works_in_development(client):
    from app.auth import service as authsvc
    from tests.test_email_delivery import _mk_user, _user_id  # reuse helpers
    email = f"p0-reset-{__import__('time').time_ns()}@test.local"
    client.post("/api/v1/auth/users", headers={
        "Authorization": "Bearer " + client.post("/api/v1/auth/login", json={
            "email": "admin@test.local", "password": "test-admin-password-A1"
        }).json()["access_token"]},
        json={"email": email, "password": "P0-Reset-Pass-1", "role": "viewer"})
    client.post("/api/v1/auth/request-password-reset", json={"email": email})
    raw = authsvc.issue_user_token(_user_id(email), "reset_password", 5)
    r = client.post("/api/v1/auth/reset-password", json={"token": raw,
                                                         "password": "P0-Reset-Pass-2"})
    assert r.status_code == 200


class _FakeSMTP:
    """Records credentials + payload without a real AUTH-capable server."""

    calls: list[str] = []

    def __init__(self, port):
        _FakeSMTP.calls = []

    def ehlo(self):
        return

    def starttls(self, context=None):
        return

    def login(self, user, password):
        _FakeSMTP.calls.append(f"{user}:{password}")

    def send_message(self, msg):
        _FakeSMTP.calls.append(msg.get_content())

    def quit(self):
        return