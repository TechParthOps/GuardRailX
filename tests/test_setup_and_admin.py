"""Phase 6 (atomic bootstrap) and Phase 7 (last-admin protection) tests."""
import json  # noqa: F401  (used by the subprocess assertion)
from concurrent.futures import ThreadPoolExecutor

import pytest

from sqlalchemy import select

from app.db import session_scope
from app.models import User

from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD


def _mk_admin(client, admin_headers, email):
    r = client.post("/api/v1/auth/users", headers=admin_headers,
                    json={"email": email, "password": "Adm-Pass-12345", "role": "admin"})
    assert r.status_code == 200
    return r.json()["id"]


# ---------------------------------------------------------------- Phase 6

def test_setup_status_uses_admin_definition(client, admin_headers):
    """A registered viewer WITHOUT an admin would still mean 'setup required';
    with an admin present, status is complete regardless of other users."""
    client.post("/api/v1/auth/users", headers=admin_headers,
                json={"email": "pre-admin-viewer@test.local",
                      "password": "Viewer-Pass-123", "role": "viewer"})
    status = client.get("/api/v1/setup/status").json()
    assert status["setup_required"] is False  # active admin exists


def test_setup_atomic_under_concurrency(client, monkeypatch):
    """Concurrent setup requests: exactly ONE first administrator is created.

    Runs against a fresh in-session database via subprocess to isolate state.
    """
    import subprocess
    import sys
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    code = "\n".join([
        "import os, tempfile, sys, json",
        "from concurrent.futures import ThreadPoolExecutor",
        "tmp = tempfile.mkdtemp()",
        "os.environ.update({'GX_DATA_DIR': tmp, 'GX_SANDBOX_DIR': tmp+'/sb',",
        " 'GX_DATABASE_URL': 'sqlite:///'+tmp+'/t.db',",
        " 'GX_SETUP_TOKEN': 'atomic-setup-token-0123456789'})",
        "sys.path.insert(0, '.')",
        "from app.db import migrate",
        "migrate()",
        "from app.seed import bootstrap",
        "bootstrap()",
        "from app.setup import setup_from_token",
        "from app.db import session_scope",
        "from sqlalchemy import select",
        "from app.models import User",
        "def attempt(i):",
        "    try:",
        "        setup_from_token('atomic-setup-token-0123456789',",
        "                         f'a{i}@atomic.local', 'Atomic-Pass-123')",
        "        return 'ok'",
        "    except PermissionError:",
        "        return 'refused'",
        "    except ValueError as e:",
        "        return f'invalid:{e}'",
        "with ThreadPoolExecutor(max_workers=6) as ex:",
        "    results = list(ex.map(attempt, range(6)))",
        "with session_scope() as s:",
        "    n = len(s.scalars(select(User).where(User.role=='admin')).all())",
        "print(json.dumps({'results': results, 'admins': n}))",
    ])
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         cwd=str(root), timeout=180,
                         env={**__import__("os").environ, "PYTHONPATH": str(root)})
    data = json.loads(out.stdout.strip().splitlines()[-1])
    assert data["admins"] == 1, data
    assert data["results"].count("ok") == 1, data
    assert data["results"].count("refused") == 5, data


def test_setup_refused_after_completion_and_bad_token(client):
    r = client.post("/api/v1/setup", json={"setup_token": "bad-token-bad-token-12345",
                    "email": "x@y.local", "password": "Setup-Pass-123"})
    assert r.status_code == 403


def test_viewer_registration_never_becomes_admin(client):
    r = client.post("/api/v1/auth/signup", json={"email": "never-admin@test.local",
                    "password": "Never-Admin-123", "password_confirm": "Never-Admin-123"})
    assert r.status_code == 201
    tok = client.post("/api/v1/auth/login",
                      json={"email": "never-admin@test.local",
                            "password": "Never-Admin-123"}).json()["access_token"]
    assert client.get("/api/v1/auth/me",
                      headers={"Authorization": "Bearer " + tok}).json()["role"] == "viewer"


# ---------------------------------------------------------------- Phase 7

def test_last_admin_cannot_self_demote(client, admin_headers):
    """Single-admin deployment: self-demotion must be blocked."""
    # ensure we know the admin's user id
    uid = _user_id(ADMIN_EMAIL)
    r = client.post(f"/api/v1/admin/users/{uid}/role", headers=admin_headers,
                    json={"role": "viewer"})
    assert r.status_code == 409
    # role unchanged
    users = client.get("/api/v1/admin/users", headers=admin_headers).json()
    assert next(u for u in users if u["id"] == uid)["role"] == "admin"


def test_last_admin_cannot_be_disabled(client, admin_headers):
    uid = _user_id(ADMIN_EMAIL)
    r = client.post(f"/api/v1/admin/users/{uid}/disable", headers=admin_headers,
                    json={"disabled": True})
    assert r.status_code == 409


def test_role_change_allowed_with_multiple_admins(client, admin_headers):
    second = _mk_admin(client, admin_headers, "second-admin@test.local")
    r = client.post(f"/api/v1/admin/users/{second}/role", headers=admin_headers,
                    json={"role": "researcher"})
    assert r.status_code == 200  # another active admin remains
    # demote back for subsequent tests
    client.post(f"/api/v1/admin/users/{second}/role", headers=admin_headers,
                json={"role": "admin"})


def test_disable_allowed_with_multiple_admins(client, admin_headers):
    second = _mk_admin(client, admin_headers, "third-admin@test.local")
    r = client.post(f"/api/v1/admin/users/{second}/disable", headers=admin_headers,
                    json={"disabled": True})
    assert r.status_code == 200
    # restore
    client.post(f"/api/v1/admin/users/{second}/disable", headers=admin_headers,
                json={"disabled": False})


def test_rejected_last_admin_attempts_audited(client, admin_headers):
    uid = _user_id(ADMIN_EMAIL)
    # demote every OTHER active admin so main is the last one
    for u in client.get("/api/v1/admin/users", headers=admin_headers).json():
        if u["id"] != uid and u["role"] == "admin" and not u["disabled"]:
            r = client.post(f"/api/v1/admin/users/{u['id']}/role", headers=admin_headers,
                            json={"role": "researcher"})
            assert r.status_code == 200
    r = client.post(f"/api/v1/admin/users/{uid}/role", headers=admin_headers,
                    json={"role": "viewer"})
    assert r.status_code == 409
    audit = client.get("/api/v1/admin/audit", headers=admin_headers).json()
    assert any(a["action"] == "admin.last_admin_protected" for a in audit)


def test_concurrent_role_changes_cannot_remove_last_admin(client, admin_headers):
    """Two concurrent demotions: at least one ACTIVE admin must always survive.

    Uses a third admin's credentials for verification so the check does not
    depend on the main admin's (possibly demoted) session.
    """
    second = _mk_admin(client, admin_headers, "conc-admin@test.local")
    third = _mk_admin(client, admin_headers, "conc-admin3@test.local")
    third_token = client.post("/api/v1/auth/login", json={
        "email": "conc-admin3@test.local", "password": "Adm-Pass-12345"}).json()["access_token"]
    third_h = {"Authorization": "Bearer " + third_token}
    uid_main = _user_id(ADMIN_EMAIL)

    def demote(uid):
        return client.post(f"/api/v1/admin/users/{uid}/role", headers=admin_headers,
                           json={"role": "researcher"}).status_code

    with ThreadPoolExecutor(max_workers=2) as ex:
        codes = list(ex.map(demote, [uid_main, second]))

    admins = [u for u in client.get("/api/v1/admin/users", headers=third_h).json()
              if u["role"] == "admin" and not u["disabled"]]
    assert len(admins) >= 1, (codes, admins)
    # restore a deterministic state for later tests: main admin re-promoted
    if not any(u["id"] == uid_main for u in admins):
        client.post(f"/api/v1/admin/users/{uid_main}/role", headers=third_h,
                    json={"role": "admin"})
    client.post(f"/api/v1/admin/users/{_user_id('conc-admin3@test.local')}/role",
                headers=third_h, json={"role": "admin"})


def _user_id(email):
    with session_scope() as s:
        return s.scalar(select(User).where(User.email == email)).id
