"""Account-token delivery + lifecycle tests (Phase 5) — no external network.

Uses a minimal in-process SMTP capture server for real SMTP-path verification.
"""
import socket
import threading
import time

import pytest


class SMTPCaptureServer(threading.Thread):
    """Minimal SMTP server capturing DATA payloads (RFC 5321 subset)."""

    def __init__(self):
        super().__init__(daemon=True)
        self.messages: list[dict] = []
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self._sock.listen(1)
        self._stop = threading.Event()

    def run(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            with conn:
                f = conn.makefile("rwb")
                conn.sendall(b"220 capture ready\r\n")
                data_mode = False
                envelope: dict = {"from": "", "to": "", "data": []}
                try:
                    for line in f:
                        if self._stop.is_set():
                            return
                        if data_mode:
                            if line.strip() == b".":
                                data_mode = False
                                self.messages.append({**envelope, "data": b"\n".join(envelope["data"]).decode()})
                                conn.sendall(b"250 queued\r\n")
                            else:
                                envelope["data"].append(line.replace(b"\r\n", b"\n"))
                            continue
                        cmd = line.strip().decode(errors="replace").upper()
                        if cmd.startswith("EHLO") or cmd.startswith("HELO"):
                            conn.sendall(b"250-capture\r\n250 OK\r\n")
                        elif cmd.startswith("MAIL FROM"):
                            envelope["from"] = cmd.split(":", 1)[-1].strip()
                            conn.sendall(b"250 OK\r\n")
                        elif cmd.startswith("RCPT TO"):
                            envelope["to"] = cmd.split(":", 1)[-1].strip()
                            conn.sendall(b"250 OK\r\n")
                        elif cmd.startswith("DATA"):
                            data_mode = True
                            conn.sendall(b"354 end with .\r\n")
                        elif cmd.startswith("QUIT"):
                            conn.sendall(b"221 bye\r\n")
                            break
                        elif cmd.startswith("STARTTLS"):
                            conn.sendall(b"454 TLS not supported by capture\r\n")
                        else:
                            conn.sendall(b"250 OK\r\n")
                except (ConnectionResetError, OSError):
                    return  # client closed mid-session (normal at teardown)

    def stop(self):
        self._stop.set()
        try:
            socket.create_connection(("127.0.0.1", self.port), timeout=1).close()
        except Exception:
            pass
        self._sock.close()


@pytest.fixture()
def smtp_server():
    s = SMTPCaptureServer()
    s.start()
    time.sleep(0.2)
    yield s
    s.stop()


def _smtp_settings(port, monkeypatch=None):
    """Mutate via monkeypatch so the lru_cached global is restored after each
    test (tests must never permanently mutate config)."""
    from app.config import get_settings
    s = get_settings()
    assert monkeypatch is not None, "use _smtp_settings(port, monkeypatch)"
    monkeypatch.setattr(s, "email_mode", "smtp")
    monkeypatch.setattr(s, "smtp_host", "127.0.0.1")
    monkeypatch.setattr(s, "smtp_port", port)
    monkeypatch.setattr(s, "smtp_use_tls", False)
    monkeypatch.setattr(s, "smtp_use_ssl", False)
    monkeypatch.setattr(s, "smtp_from", "gx@test.local")
    monkeypatch.setattr(s, "smtp_timeout_seconds", 5.0)
    return s


# ------------------------------------------------------------- delivery path

def test_smtp_delivery_delivers_token(smtp_server, monkeypatch):
    from app import mailer
    s = _smtp_settings(smtp_server.port, monkeypatch)
    monkeypatch.setattr(mailer, "get_settings", lambda: s)
    mailer.send_account_token("user@test.local", "reset_password", "RAW-TOKEN-123")
    time.sleep(0.3)
    assert smtp_server.messages, "SMTP server captured nothing"
    msg = smtp_server.messages[0]
    assert "user@test.local".lower() in msg["to"].lower()
    assert "RAW-TOKEN-123" in msg["data"]
    assert "password reset" in msg["data"].lower()


def test_smtp_delivery_failure_raises(monkeypatch):
    from app import mailer
    s = _smtp_settings(1, monkeypatch)  # unreachable port
    s.smtp_timeout_seconds = 2.0
    monkeypatch.setattr(mailer, "get_settings", lambda: s)
    with pytest.raises(mailer.DeliveryError):
        mailer.send_account_token("user@test.local", "verify_email", "TOK")


def test_console_mode_delivery_is_labeled(monkeypatch, capsys):
    from app import mailer
    s = get_settings_like_console(monkeypatch)
    monkeypatch.setattr(mailer, "get_settings", lambda: s)
    mailer.send_account_token("user@test.local", "verify_email", "DEV-TOKEN-1")
    out = capsys.readouterr().out
    assert "mode=console" in out and "DEV-TOKEN-1" in out


def get_settings_like_console(monkeypatch):
    from app.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "email_mode", "console")
    return s


def test_delivery_ready_semantics(monkeypatch):
    from app.config import get_settings
    from app.mailer import delivery_ready
    s = get_settings()
    monkeypatch.setattr(s, "email_mode", "smtp")
    monkeypatch.setattr(s, "smtp_host", "")
    ok, why = delivery_ready()
    assert not ok and "GX_SMTP_HOST" in why
    monkeypatch.setattr(s, "smtp_host", "smtp.example.com")
    ok, _ = delivery_ready()
    assert ok
    monkeypatch.setattr(s, "email_mode", "console")
    monkeypatch.setattr(s, "environment", "production")
    monkeypatch.setattr(s, "require_email_verification", True)
    ok, why = delivery_ready()
    assert not ok and "console" in why


def test_production_startup_refuses_missing_delivery():
    import subprocess
    import sys
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    code = "\n".join([
        "import os, tempfile, sys",
        "tmp = tempfile.mkdtemp()",
        "os.environ.update({'GX_DATA_DIR': tmp, 'GX_SANDBOX_DIR': tmp+'/sb',",
        " 'GX_DATABASE_URL': 'sqlite:///'+tmp+'/t.db', 'GX_ENVIRONMENT': 'production',",
        " 'GX_SECRET_KEY': 'x'*48, 'GX_CORS_ORIGINS': 'https://x.example.com',",
        " 'GX_REQUIRE_EMAIL_VERIFICATION': 'true', 'GX_EMAIL_MODE': 'console'})",
        "sys.path.insert(0, '.')",
        "from fastapi.testclient import TestClient",
        "from app.main import create_app",
        "try:",
        "    with TestClient(create_app()) as c: c.get('/api/v1/health'); print('STARTED')",
        "except RuntimeError as e:",
        "    print('REFUSED:', str(e)[:160])",
    ])
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         cwd=str(root), timeout=120)
    assert "REFUSED" in out.stdout and "console token delivery" in out.stdout, out.stdout + out.stderr


# --------------------------------------------------------- token lifecycle

def _mk_user():
    from app.auth import service as authsvc
    from app.db import session_scope
    with session_scope() as s:
        u = authsvc.create_user(f"tok-{time.time_ns()}@test.local", "Token-Pass-123", "viewer")
        return u.id


def test_token_rotation_invalidates_previous():
    from app.auth import service as authsvc
    uid = _mk_user()
    t1 = authsvc.issue_user_token(uid, "reset_password", 10)
    t2 = authsvc.issue_user_token(uid, "reset_password", 10)
    assert authsvc.consume_user_token(t1, "reset_password") is None  # rotated away
    assert authsvc.consume_user_token(t2, "reset_password") == uid


def test_expired_token_rejected():
    from datetime import datetime, timedelta, timezone
    from app.auth import service as authsvc
    from app.db import session_scope
    from app.models import UserToken
    uid = _mk_user()
    raw = authsvc.issue_user_token(uid, "reset_password", 10)
    with session_scope() as s:
        from sqlalchemy import select
        th = authsvc._hash_token(raw)
        row = s.scalar(select(UserToken).where(UserToken.token_hash == th))
        row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    assert authsvc.consume_user_token(raw, "reset_password") is None


def test_duplicate_use_rejected():
    from app.auth import service as authsvc
    uid = _mk_user()
    raw = authsvc.issue_user_token(uid, "verify_email", 10)
    assert authsvc.consume_user_token(raw, "verify_email") == uid
    assert authsvc.consume_user_token(raw, "verify_email") is None  # single-use


def test_wrong_kind_rejected():
    from app.auth import service as authsvc
    uid = _mk_user()
    raw = authsvc.issue_user_token(uid, "verify_email", 10)
    assert authsvc.consume_user_token(raw, "reset_password") is None


def test_reset_token_single_use_concurrent():
    """Two concurrent consumers: AT MOST ONE may succeed (row-lock atomicity)."""
    from concurrent.futures import ThreadPoolExecutor
    from app.auth import service as authsvc
    uid = _mk_user()
    raw = authsvc.issue_user_token(uid, "reset_password", 10)
    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(lambda _: authsvc.consume_user_token(raw, "reset_password"),
                              range(8)))
    winners = [r for r in results if r == uid]
    assert len(winners) == 1, results


def test_password_reset_endpoint_revokes_and_changes(client, admin_headers):
    """End-to-end reset via the API against a DEDICATED account (must not
    disturb the shared admin session other tests rely on)."""
    email = f"reset-e2e-{time.time_ns()}@test.local"
    r = client.post("/api/v1/auth/users", headers=admin_headers,
                    json={"email": email, "password": "Reset-E2E-Pass-1", "role": "viewer"})
    assert r.status_code == 200
    old_session = client.post("/api/v1/auth/login",
                              json={"email": email, "password": "Reset-E2E-Pass-1"}).json()["access_token"]
    # request reset -> generic response; delivery succeeds in console mode
    r = client.post("/api/v1/auth/request-password-reset", json={"email": email})
    assert r.status_code == 200
    from app.auth import service as authsvc
    raw = authsvc.issue_user_token(_user_id(email), "reset_password", 5)
    r2 = client.post("/api/v1/auth/reset-password", json={"token": raw,
                                                          "password": "Reset-E2E-Pass-2"})
    assert r2.status_code == 200
    # old session revoked by the reset
    assert client.get("/api/v1/auth/me",
                      headers={"Authorization": "Bearer " + old_session}).status_code == 401
    # new password works
    assert client.post("/api/v1/auth/login",
                       json={"email": email, "password": "Reset-E2E-Pass-2"}).status_code == 200


def _user_id(email):
    from sqlalchemy import select
    from app.db import session_scope
    from app.models import User
    with session_scope() as s:
        return s.scalar(select(User).where(User.email == email)).id
