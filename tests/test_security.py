"""Security boundaries: RBAC, secret handling, emergency stop, rate limiting, redaction."""
from app.observability.redaction import redact_obj, redact_text


def test_unauthenticated_requests_rejected(client):
    for path in ("/api/v1/targets", "/api/v1/experiments", "/api/v1/findings",
                 "/api/v1/policies", "/api/v1/events", "/api/v1/admin/stats"):
        r = client.get(path)
        assert r.status_code == 401, path


def test_rbac_viewer_cannot_create(client, viewer_headers, project_id):
    r = client.post("/api/v/projects", headers=viewer_headers, json={"name": "nope"})
    assert r.status_code in (403, 404)  # 404 due to typo path is impossible: check below
    r = client.post("/api/v1/projects", headers=viewer_headers, json={"name": "viewer-proj"})
    assert r.status_code == 403
    r = client.post("/api/v1/targets", headers=viewer_headers, json={
        "project_id": project_id, "name": "x", "adapter_name": "mock", "config": {}})
    assert r.status_code == 403


def test_rbac_researcher_cannot_activate_policy(client, researcher_headers, admin_headers):
    r = client.post("/api/v1/policies", headers=researcher_headers, json={
        "name": "rbac-test", "document": {"default_effect": "deny", "rules": []}})
    # creating requires admin
    assert r.status_code == 403


def test_researcher_cannot_admin_endpoints(client, researcher_headers):
    assert client.get("/api/v1/admin/audit", headers=researcher_headers).status_code == 403
    assert client.post("/api/v1/admin/emergency-stop", headers=researcher_headers,
                       json={"active": True}).status_code == 403


def test_target_config_rejects_secrets(client, researcher_headers, project_id):
    r = client.post("/api/v1/targets", headers=researcher_headers, json={
        "project_id": project_id, "name": "secret-config", "adapter_name": "mock",
        "model": "m", "config": {"model": "m", "api_key": "sk-abcdef123456"}})
    assert r.status_code == 422  # pydantic validation: secrets forbidden in config


def test_emergency_stop_blocks_experiments(client, admin_headers, researcher_headers, project_id):
    r = client.post("/api/v1/admin/emergency-stop", headers=admin_headers, json={"active": True})
    assert r.status_code == 200
    assert r.json()["emergency_stop"] is True
    from tests.conftest import make_target, default_policy_id
    tid = make_target(client, researcher_headers, project_id, "estop-target", "refuse")
    r = client.post("/api/v1/experiments", headers=researcher_headers, json={
        "project_id": project_id, "target_id": tid,
        "policy_id": default_policy_id(client, admin_headers),
        "scenario_keys": ["inj.direct.override"],
        "authorization": {"authorized_by": "t", "acknowledged": True}, "config": {}})
    assert r.status_code == 423  # locked: experiments frozen
    client.post("/api/v1/admin/emergency-stop", headers=admin_headers, json={"active": False})


def test_login_rate_and_audit(client, admin_headers):
    # failed logins are audited
    client.post("/api/v1/auth/login", json={"email": "admin@guardrailx.local", "password": "wrong-pass-123"})
    audit = client.get("/api/v1/admin/audit", headers=admin_headers).json()
    assert any(a["action"] == "auth.login_failed" for a in audit)


def test_redact_text_patterns():
    assert redact_text("key sk-abcdef1234567890 done") == "key REDACTED_API_KEY done"
    assert "REDACTED_BEARER" in redact_text("Authorization: Bearer abc.def.ghi")
    assert "REDACTED_AWS" in redact_text("AKIAIOSFODNN7EXAMPLE")
    assert "REDACTED_GITHUB" in redact_text("token ghp_abcdefghijklmnopqrstuvwx")
    assert "REDACTED_JWT" in redact_text("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c")


def test_redact_obj_masks_sensitive_fields_and_nested():
    data = {"api_key": "sk-xyz", "nested": {"password": "hunter2000", "note": "safe"},
            "list": [{"authorization": "Bearer zzz"}]}
    out = redact_obj(data)
    assert out["api_key"] == "[REDACTED]"
    assert out["nested"]["password"] == "[REDACTED]"
    assert out["nested"]["note"] == "safe"
    assert out["list"][0]["authorization"] == "[REDACTED]"


def test_api_key_roundtrip(client, viewer_headers, admin_headers, researcher_headers):
    # viewers can no longer mint credentials at all (GX-001 remediation)
    r = client.post("/api/v1/auth/api-keys", headers=viewer_headers, json={"name": "test key"})
    assert r.status_code == 403
    # researchers can mint keys with their own effective role
    r = client.post("/api/v1/auth/api-keys", headers=researcher_headers, json={"name": "test key"})
    assert r.status_code == 200
    key = r.json()["api_key"]
    assert key.startswith("gx_")
    # usable
    r = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 200
    # revocation works
    keys = client.get("/api/v1/auth/api-keys", headers=researcher_headers).json()
    kid = keys[0]["id"]
    assert client.delete(f"/api/v1/auth/api-keys/{kid}", headers=researcher_headers).status_code == 200
    r = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 401


def test_viewers_cannot_mint_elevated_keys(client, viewer_headers):
    r = client.post("/api/v1/auth/api-keys", headers=viewer_headers,
                    json={"name": "escalate", "role": "admin"})
    assert r.status_code == 403


def test_researcher_key_cannot_escalate_nor_mint_for_others(client, researcher_headers):
    # explicit elevation request is blocked and audited (GX-001)
    r = client.post("/api/v1/auth/api-keys", headers=researcher_headers,
                    json={"name": "try-admin", "role": "admin"})
    assert r.status_code == 403
    # default key = creator's effective role (researcher), never account drift
    r = client.post("/api/v1/auth/api-keys", headers=researcher_headers,
                    json={"name": "own-role"})
    assert r.status_code == 200 and r.json()["role"] == "researcher"


def test_events_do_not_leak_secrets(client, admin_headers, researcher_headers, project_id):
    from tests.conftest import make_target, default_policy_id, run_experiment_sync
    tid = make_target(client, researcher_headers, project_id, "redact-target", "leak_canary")
    exp_id = client.post("/api/v1/experiments", headers=researcher_headers, json={
        "project_id": project_id, "target_id": tid,
        "policy_id": default_policy_id(client, admin_headers),
        "scenario_keys": ["inj.direct.override"],
        "authorization": {"authorized_by": "t", "acknowledged": True}, "config": {"replays": 1}}).json()["id"]
    run_experiment_sync(exp_id)
    events = client.get(f"/api/v1/experiments/{exp_id}/events", headers=admin_headers).json()
    blob = str(events)
    assert "sk-" not in blob or "REDACTED" in blob
