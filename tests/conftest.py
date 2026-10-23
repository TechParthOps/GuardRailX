import os
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="gx_test_")
os.environ["GX_DATA_DIR"] = TMP
os.environ["GX_SANDBOX_DIR"] = os.path.join(TMP, "sandbox")
os.environ["GX_DATABASE_URL"] = "sqlite:///" + os.path.join(TMP, "test.db").replace("\\", "/")
os.environ["GX_ENVIRONMENT"] = "development"
os.environ["GX_CASE_REPLAYS"] = "2"
os.environ["GX_SETUP_TOKEN"] = "test-setup-token-0123456789"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

ADMIN_EMAIL = "admin@test.local"
ADMIN_PASSWORD = "test-admin-password-A1"


@pytest.fixture(scope="session", autouse=True)
def _database(app):
    """Ensure every test session has a migrated, bootstrapped database."""
    yield


@pytest.fixture(scope="session")
def app():
    from app.main import create_app
    from app.seed import bootstrap
    from app.setup import setup_from_token
    bootstrap()
    setup_from_token(os.environ["GX_SETUP_TOKEN"], ADMIN_EMAIL, ADMIN_PASSWORD)
    yield create_app()


@pytest.fixture(scope="session")
def client(app):
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def admin_headers(client):
    r = client.post("/api/v1/auth/login",
                    json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["access_token"]}


@pytest.fixture(scope="session")
def researcher_headers(client, admin_headers):
    r = client.post("/api/v1/auth/users", headers=admin_headers,
                    json={"email": "researcher@guardrailx.local",
                          "password": "Researcher-Pass-123", "role": "researcher"})
    assert r.status_code in (200, 409)
    r = client.post("/api/v1/auth/login",
                    json={"email": "researcher@guardrailx.local", "password": "Researcher-Pass-123"})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["access_token"]}


@pytest.fixture(scope="session")
def viewer_headers(client, admin_headers):
    r = client.post("/api/v1/auth/users", headers=admin_headers,
                    json={"email": "viewer@guardrailx.local",
                          "password": "Viewer-Pass-12345", "role": "viewer"})
    assert r.status_code in (200, 409)
    r = client.post("/api/v1/auth/login",
                    json={"email": "viewer@guardrailx.local", "password": "Viewer-Pass-12345"})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["access_token"]}


@pytest.fixture(scope="session")
def project_id(client, researcher_headers):
    r = client.post("/api/v1/projects", headers=researcher_headers,
                    json={"name": "Test Project", "description": "automated tests"})
    if r.status_code == 409:
        projects = client.get("/api/v1/projects", headers=researcher_headers).json()
        return next(p["id"] for p in projects if p["name"] == "Test Project")
    return r.json()["id"]


def make_target(client, headers, project_id, name, behavior, extra=None):
    r = client.post("/api/v1/targets", headers=headers, json={
        "project_id": project_id, "name": name, "adapter_name": "mock",
        "model": "mock-model",
        "config": {"model": "mock-model", "behavior": behavior, **(extra or {})},
    })
    assert r.status_code == 200, r.text
    target_id = r.json()["id"]
    # mock adapter health test marks it operational
    r = client.post(f"/api/v1/targets/{target_id}/test-connection", headers=headers)
    assert r.status_code == 200 and r.json()["status"] == "operational", r.text
    return target_id


def default_policy_id(client, admin_headers):
    pols = client.get("/api/v1/policies", headers=admin_headers).json()
    active = [p for p in pols if p["active"] and p["name"] == "default"]
    assert active, "default policy missing"
    return active[0]["id"]


def run_experiment_sync(exp_id):
    import asyncio
    from app.experiments import orchestrator as orch
    asyncio.run(orch.run_experiment(exp_id))

@pytest.fixture(autouse=True)
def _clear_auth_rate_store():
    """Auth rate limits are per-IP; tests share one client IP. Clear before and
    after each test so unrelated tests stay deterministic (the dedicated
    rate-limit test fills and asserts the mechanism itself)."""
    from app.api.v1 import routes
    routes._rate_store.clear()
    yield
    routes._rate_store.clear()