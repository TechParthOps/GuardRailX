import logging
import os
import sys
import tempfile

logging.disable(logging.WARNING)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TMP = tempfile.mkdtemp(prefix="gx_poc4_")
os.environ.update({
    "GX_DATA_DIR": TMP,
    "GX_SANDBOX_DIR": TMP + "/sandbox",
    "GX_DATABASE_URL": "sqlite:///" + TMP.replace("\\", "/") + "/poc.db",
    "GX_ADMIN_PASSWORD": "poc-admin-password-123",
    "GX_SEED_DEMO_DATA": "true",
})

from fastapi.testclient import TestClient  # noqa: E402
from app.main import create_app  # noqa: E402
from app.seed import bootstrap  # noqa: E402

bootstrap()
app = create_app()
c = TestClient(app)
r = c.post("/api/v1/auth/login", json={"email": "admin@guardrailx.local", "password": "poc-admin-password-123"})
h = {"Authorization": "Bearer " + r.json()["access_token"]}
prj = c.get("/api/v1/projects", headers=h).json()[0]["id"]
t = c.post("/api/v1/targets", headers=h, json={"project_id": prj, "name": "flaky-provider",
          "adapter_name": "mock", "model": "mock-model",
          "config": {"model": "mock-model", "behavior": "flaky", "flaky_failures": 100}}).json()
c.post(f"/api/v1/targets/{t['id']}/test-connection", headers=h)
pol = c.get("/api/v1/policies", headers=h).json()[0]
b = c.post("/api/v1/benchmarks/run", headers=h, json={
    "project_id": prj, "target_id": t["id"], "policy_id": pol["id"], "suite_key": "safety-core",
    "authorization": {"authorized_by": "poc", "acknowledged": True}, "config": {}})
print("benchmark HTTP:", b.status_code)
runs = c.get("/api/v1/benchmarks", headers=h).json()[0]
print("run status:", runs["status"])
m = (runs.get("metrics") or {}).get("metrics", {})
print("infra_error_rate:", m.get("infra_error_rate", {}).get("value"),
      "| policy_violation_rate:", m.get("policy_violation_rate", {}).get("value"))
verdict = runs["status"] == "completed" and m.get("infra_error_rate", {}).get("value") == 1.0
print("=> GX-004", "CONFIRMED" if verdict else "not reproduced")
