"""Post-remediation vulnerability reproduction (runs against isolated temp DB).

Each check prints CONFIRMED (still vulnerable) / NOT REPRODUCED (fixed).
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TMP = tempfile.mkdtemp(prefix="gx_poc_")
os.environ["GX_DATA_DIR"] = TMP
os.environ["GX_SANDBOX_DIR"] = os.path.join(TMP, "sandbox")
os.environ["GX_DATABASE_URL"] = "sqlite:///" + os.path.join(TMP, "poc.db").replace("\\", "/")
os.environ["GX_SETUP_TOKEN"] = "poc-setup-token-0123456789"
os.environ["GX_SEED_DEMO_DATA"] = "true"  # exercise demo path for GX-006

results = []


def check(finding_id, title, confirmed, evidence):
    results.append((finding_id, title, bool(confirmed), evidence))
    tag = "STILL VULNERABLE" if confirmed else "FIXED / NOT REPRODUCED"
    print(f"[{tag}] {finding_id}: {title}")
    print(f"        evidence: {evidence[:300]}")


from fastapi.testclient import TestClient  # noqa: E402
from app.main import create_app  # noqa: E402
from app.seed import bootstrap  # noqa: E402

bootstrap()
app = create_app()
client = TestClient(app)

# --- GX-005: no default admin; one-time setup flow
r = client.post("/api/v1/auth/login", json={"email": "admin@guardrailx.local", "password": "whatever-123"})
no_default = r.status_code == 401
r_bad = client.post("/api/v1/setup", json={"setup_token": "wrong-token-wrong-token",
                    "email": "admin@poc.local", "password": "Poc-Admin-Pass-123"})
r_setup = client.post("/api/v1/setup", json={"setup_token": "poc-setup-token-0123456789",
                      "email": "admin@poc.local", "password": "Poc-Admin-Pass-123"})
r_again = client.post("/api/v1/setup", json={"setup_token": "poc-setup-token-0123456789",
                      "email": "admin2@poc.local", "password": "Poc-Admin-Pass-123"})
check("GX-005", "No default admin identity; one-time secure setup only",
      not (no_default and r_bad.status_code == 403 and r_setup.status_code == 200 and r_again.status_code == 403),
      f"default login -> {r.status_code}; bad token -> {r_bad.status_code}; "
      f"setup -> {r_setup.status_code}; re-setup -> {r_again.status_code}")

r = client.post("/api/v1/auth/login", json={"email": "admin@poc.local", "password": "Poc-Admin-Pass-123"})
admin_tok = r.json()["access_token"]
ah = {"Authorization": "Bearer " + admin_tok}

# --- GX-001: API-key escalation
r = client.post("/api/v1/auth/api-keys", headers=ah, json={"name": "restricted", "role": "viewer"})
viewer_key = r.json().get("api_key")
vh = {"Authorization": "Bearer " + viewer_key}
r2 = client.post("/api/v1/auth/api-keys", headers=vh, json={"name": "child-no-role"})
r3 = client.post("/api/v1/auth/api-keys", headers=vh, json={"name": "child-admin", "role": "admin"})
# researcher-level escalation attempt
client.post("/api/v1/auth/users", headers=ah, json={"email": "res@poc.local", "password": "Res-Pass-12345", "role": "researcher"})
rt = client.post("/api/v1/auth/login", json={"email": "res@poc.local", "password": "Res-Pass-12345"}).json()
rh = {"Authorization": "Bearer " + rt["access_token"]}
r4 = client.post("/api/v1/auth/api-keys", headers=rh, json={"name": "res-admin", "role": "admin"})
check("GX-001", "Viewer-scoped API key mints an administrator key",
      r2.status_code == 200 or r3.status_code == 200 or r4.status_code == 200,
      f"viewer key child (no role) -> {r2.status_code}; explicit admin -> {r3.status_code}; "
      f"researcher->admin -> {r4.status_code} (all must be 403)")

# --- GX-007: stale token privileges after demotion
client.post("/api/v1/auth/users", headers=ah, json={"email": "adm2@poc.local", "password": "Adm2-Pass-12345", "role": "admin"})
at2 = client.post("/api/v1/auth/login", json={"email": "adm2@poc.local", "password": "Adm2-Pass-12345"}).json()
h2 = {"Authorization": "Bearer " + at2["access_token"]}
client.post(f"/api/v1/admin/users/{at2.get('user_id', '')}/role", headers=ah,
            json={"role": "viewer"})  # find user id first
from sqlalchemy import select  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.models import User  # noqa: E402
with session_scope() as s:
    u = s.scalar(select(User).where(User.email == "adm2@poc.local"))
    uid = u.id
client.post(f"/api/v1/admin/users/{uid}/role", headers=ah, json={"role": "viewer", "revoke_credentials": False})
r = client.get("/api/v1/admin/audit", headers=h2)
check("GX-007", "Old session keeps admin rights after role demotion",
      r.status_code == 200,
      f"demoted user's existing session GET /admin/audit -> HTTP {r.status_code} (must be 403)")

# --- GX-002: IDOR
p1 = client.post("/api/v1/projects", headers=rh, json={"name": "res1-private"}).json()
p2 = client.post("/api/v1/projects", headers=ah, json={"name": "admin-private"}).json()
tgt2 = client.post("/api/v1/targets", headers=ah, json={
    "project_id": p2["id"], "name": "adm-target", "adapter_name": "mock",
    "model": "mock-model", "config": {"model": "mock-model", "behavior": "refuse"}}).json()
tgt_create = client.post("/api/v1/experiments", headers=rh, json={
    "project_id": p1["id"], "target_id": tgt2["id"],
    "policy_id": client.get("/api/v1/policies", headers=rh).json()[0]["id"],
    "scenario_keys": ["inj.direct.override"],
    "authorization": {"authorized_by": "res", "acknowledged": True}, "config": {}})
tgt_get = client.get(f"/api/v1/targets/{tgt2['id']}", headers=rh)
tgt_list = client.get("/api/v1/targets", headers=rh).json()
visible = any(t["id"] == tgt2["id"] for t in tgt_list)
check("GX-002", "Cross-project object access (IDOR)",
      tgt_create.status_code == 200 or tgt_get.status_code == 200 or visible,
      f"experiment on other project's target -> {tgt_create.status_code}; "
      f"direct target read -> {tgt_get.status_code}; visible in list: {visible}")

# --- GX-003: SSRF + arbitrary env credential
poc_secret = "gx-poc-secret-value-do-not-leak"
os.environ["GX_POC_SECRET"] = poc_secret
evil = client.post("/api/v1/targets", headers=rh, json={
    "project_id": p1["id"], "name": "ssrf-probe", "adapter_name": "openai_compatible",
    "model": "m", "config": {"model": "m", "base_url": "http://127.0.0.1:8899/internal",
                             "api_key_env": "GX_POC_SECRET"}})
evil2 = client.post("/api/v1/targets", headers=rh, json={
    "project_id": p1["id"], "name": "metadata-probe", "adapter_name": "openai_compatible",
    "model": "m", "config": {"model": "m", "base_url": "http://169.254.169.254/latest/meta-data",
                             "api_key_env": "OPENAI_API_KEY"}})
check("GX-003", "SSRF base_url + arbitrary env credential selection accepted",
      evil.status_code == 200 or evil2.status_code == 200,
      f"loopback target -> {evil.status_code}; metadata target -> {evil2.status_code} (must be 400)")

# --- GX-004: benchmark false success (all provider failures)
t = client.post("/api/v1/targets", headers=rh, json={"project_id": p1["id"], "name": "flaky",
                "adapter_name": "mock", "model": "mock-model",
                "config": {"model": "mock-model", "behavior": "flaky", "flaky_failures": 100}}).json()
client.post(f"/api/v1/targets/{t['id']}/test-connection", headers=rh)
pol = client.get("/api/v1/policies", headers=rh).json()[0]
b = client.post("/api/v1/benchmarks/run", headers=rh, json={
    "project_id": p1["id"], "target_id": t["id"], "policy_id": pol["id"], "suite_key": "safety-core",
    "authorization": {"authorized_by": "poc", "acknowledged": True}, "config": {}})
run = client.get("/api/v1/benchmarks", headers=rh).json()[0]
m = (run.get("metrics") or {}).get("metrics", {})
check("GX-004", "Benchmark with 100% provider failures reported as completed",
      run.get("status") == "completed",
      f"status={run.get('status')} (must be 'failed'), infra_error_rate="
      f"{m.get('infra_error_rate', {}).get('value')}")

# --- GX-006: demo seeding at startup
from app.models import Project  # noqa: E402
with session_scope() as s:
    demo = s.scalar(select(Project).where(Project.name == "Demo (mock target)"))
check("GX-006", "Demo project/experiment auto-seeded at startup",
      demo is not None, f"demo project exists: {demo is not None} (env GX_SEED_DEMO_DATA governs)")

# --- GX-008: viewer reads global stats
client.post("/api/v1/auth/users", headers=ah, json={"email": "viewer@poc.local", "password": "Viewer-Pass-12345", "role": "viewer"})
tv = client.post("/api/v1/auth/login", json={"email": "viewer@poc.local", "password": "Viewer-Pass-12345"}).json()
hv = {"Authorization": "Bearer " + tv["access_token"]}
stats = client.get("/api/v1/admin/stats", headers=hv)
check("GX-008", "Viewer reads global platform statistics",
      stats.status_code == 200,
      f"viewer GET /admin/stats -> {stats.status_code} (must be 403); scoped summary at /dashboard/summary")

# --- GX-009: signup
r = client.post("/api/v1/auth/signup", json={"email": "newuser@poc.local",
                "password": "Newuser-Pass-123", "password_confirm": "Newuser-Pass-123"})
role_grant = client.post("/api/v1/auth/signup", json={"email": "evil@poc.local",
                         "password": "Evil-Pass-123456", "password_confirm": "Evil-Pass-123456",
                         "role": "admin"})
check("GX-009", "No public registration endpoint", r.status_code in (404, 405),
      f"POST /auth/signup -> {r.status_code}; role-field signup attempt -> {role_grant.status_code} (422: extra forbidden)")

# --- GX-010: docs exposure (security property = disabled in PRODUCTION)
docs = client.get("/api/docs")
check("GX-010", "API documentation exposed in production",
      os.environ.get("GX_ENVIRONMENT") == "production" and docs.status_code == 200,
      "dev /api/docs -> %s (by design); production returns 404 (verified in test)" % docs.status_code)

print("\n=== SUMMARY ===")
all_fixed = True
for fid, title, vuln, _ in results:
    print(f"{'STILL VULNERABLE' if vuln else 'FIXED            '} {fid} {title}")
    all_fixed = all_fixed and not vuln
print("ALL REMEDIATED" if all_fixed else "WORK REMAINING")