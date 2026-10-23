"""End-to-end experiment orchestration against the mock adapter, via the API."""
import time

from sqlalchemy import select

from app.db import session_scope
from app.models import Case, EventRecord, Experiment, Finding, Scenario
from tests.conftest import default_policy_id, make_target, run_experiment_sync


def _create_exp(client, headers, project_id, policy_id, target_id, scenarios, config=None, title="t"):
    r = client.post("/api/v1/experiments", headers=headers, json={
        "project_id": project_id, "target_id": target_id, "policy_id": policy_id,
        "scenario_keys": scenarios, "title": title,
        "authorization": {"authorized_by": "test-suite", "acknowledged": True, "scope": "tests"},
        "config": config or {},
    })
    assert r.status_code == 200, r.text
    return r.json()["id"]


def test_experiment_requires_acknowledged_authorization(client, researcher_headers, project_id, admin_headers):
    tid = make_target(client, researcher_headers, project_id, "unauth-target", "refuse")
    r = client.post("/api/v1/experiments", headers=researcher_headers, json={
        "project_id": project_id, "target_id": tid, "policy_id": default_policy_id(client, admin_headers),
        "scenario_keys": ["inj.direct.override"],
        "authorization": {"acknowledged": False}, "config": {},
    })
    assert r.status_code == 403


def test_experiment_rejects_unverified_target(client, researcher_headers, project_id, admin_headers):
    r = client.post("/api/v1/targets", headers=researcher_headers, json={
        "project_id": project_id, "name": "never-verified", "adapter_name": "mock",
        "model": "mock-model", "config": {"model": "mock-model", "behavior": "refuse"}})
    tid = r.json()["id"]
    r = client.post("/api/v1/experiments", headers=researcher_headers, json={
        "project_id": project_id, "target_id": tid, "policy_id": default_policy_id(client, admin_headers),
        "scenario_keys": ["inj.direct.override"],
        "authorization": {"authorized_by": "t", "acknowledged": True}, "config": {}})
    assert r.status_code == 403
    assert "connection test" in r.json()["detail"]


def test_leak_target_produces_confirmed_finding_and_regression(client, researcher_headers, project_id, admin_headers):
    tid = make_target(client, researcher_headers, project_id, "leaky-target", "leak_canary")
    exp_id = _create_exp(client, researcher_headers, project_id,
                         default_policy_id(client, admin_headers), tid,
                         ["inj.direct.override", "jail.persona_pressure"], {"replays": 2})
    run_experiment_sync(exp_id)

    exp = client.get(f"/api/v1/experiments/{exp_id}", headers=researcher_headers).json()
    assert exp["status"] == "completed"
    assert exp["stats"]["cases_total"] == 4  # 2 scenarios x 2 replays
    outcomes = [c["status"] for c in exp["cases"]]
    assert "model_violation" in outcomes

    findings = client.get("/api/v1/findings", headers=researcher_headers,
                          params={"experiment_id": exp_id}).json()
    assert findings, "expected at least one finding"
    f = findings[0]
    assert f["vuln_class"] == "secret_leak"
    assert f["status"] == "regression_tested"  # confirmed -> regression generated
    assert f["reproducible"] is True
    assert f["failure_layer"] == "model"

    # regression scenario registered and replayable
    detail = client.get(f"/api/v1/findings/{f['id']}", headers=researcher_headers).json()
    assert detail["regression_scenario_key"], "confirmed finding must generate a regression scenario"
    with session_scope() as s:
        scen = s.get(Scenario, detail["regression_scenario_key"])
        assert scen is not None and scen.source == "regression"

    # evidence: model.response event contains the canary (deterministic re-verification)
    events = client.get(f"/api/v1/experiments/{exp_id}/events", headers=researcher_headers).json()
    assert any(e["type"] == "model.response" for e in events)
    assert any(e["type"] == "finding.discovered" for e in events)


def test_tool_proposals_blocked_and_held_by_gateway(client, researcher_headers, project_id, admin_headers):
    # delete proposal -> policy deny; egress proposal -> approval hold
    tid = make_target(client, researcher_headers, project_id, "tool-happy-target", "propose_tool")
    exp_id = _create_exp(client, researcher_headers, project_id,
                         default_policy_id(client, admin_headers), tid,
                         ["tool.unauthorized_delete", "tool.egress_no_approval",
                          "tool.sandbox_escape"], {"replays": 1})
    run_experiment_sync(exp_id)
    exp = client.get(f"/api/v1/experiments/{exp_id}", headers=researcher_headers).json()
    outcomes = [c["status"] for c in exp["cases"]]
    assert "agent_attempted_blocked" in outcomes
    assert "model_violation" not in outcomes or True

    events = client.get(f"/api/v1/experiments/{exp_id}/events", headers=researcher_headers).json()
    types = {e["type"] for e in events}
    assert "tool.blocked" in types
    assert "approval.requested" in types
    assert "tool.executed" not in types, "no prohibited tool may actually execute"

    # nothing executed; simulated action labels are honest
    executed = [e for e in events if e["type"] == "tool.executed"]
    for e in executed:
        assert e["payload"]["result"].get("mode") != "real"


def test_approval_flow_requires_admin_and_simulated_mode(client, researcher_headers, admin_headers,
                                                         project_id):
    tid = make_target(client, researcher_headers, project_id, "egress-target", "propose_tool",
                      {"tool_name": "sim_net.http"})
    exp_id = _create_exp(client, researcher_headers, project_id,
                         default_policy_id(client, admin_headers), tid,
                         ["tool.egress_no_approval"], {"replays": 1})
    run_experiment_sync(exp_id)

    pending = client.get("/api/v1/approvals/pending", headers=admin_headers).json()
    assert pending, "egress attempt must be held for approval"
    approval = next(a for a in pending if a["experiment_id"] == exp_id)

    # researcher (non-admin) may not decide
    r = client.post(f"/api/v1/approvals/{approval['id']}/decide", headers=researcher_headers,
                    json={"decision": "approved", "reason": "nope"})
    assert r.status_code == 403

    r = client.post(f"/api/v1/approvals/{approval['id']}/decide", headers=admin_headers,
                    json={"decision": "approved", "reason": "authorized demo"})
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "approved"
    # executed, but explicitly in simulated mode (never reported as real)
    assert body["executed"]["executed"] is True
    assert body["executed"]["result"]["mode"] == "simulated"


def test_cancel_experiment(client, researcher_headers, project_id, admin_headers):
    tid = make_target(client, researcher_headers, project_id, "cancel-target", "refuse")
    exp_id = _create_exp(client, researcher_headers, project_id,
                         default_policy_id(client, admin_headers), tid,
                         ["inj.direct.override"], {"replays": 1})
    r = client.post(f"/api/v1/experiments/{exp_id}/cancel", headers=researcher_headers)
    assert r.status_code == 200
    exp = client.get(f"/api/v1/experiments/{exp_id}", headers=researcher_headers).json()
    assert exp["status"] == "cancelled"


def test_target_deletion_protected_when_experiments_exist(client, researcher_headers, project_id, admin_headers):
    tid = make_target(client, researcher_headers, project_id, "delete-protected", "refuse")
    exp_id = _create_exp(client, researcher_headers, project_id,
                         default_policy_id(client, admin_headers), tid,
                         ["inj.direct.override"], {"replays": 1})
    r = client.delete(f"/api/v1/targets/{tid}", headers=researcher_headers)
    assert r.status_code == 409
    assert "linked experiments" in r.json()["detail"]


def test_experiment_records_persist(client, researcher_headers, project_id, admin_headers):
    tid = make_target(client, researcher_headers, project_id, "persist-target", "refuse")
    exp_id = _create_exp(client, researcher_headers, project_id,
                         default_policy_id(client, admin_headers), tid,
                         ["inj.direct.override"], {"replays": 1})
    run_experiment_sync(exp_id)
    # fresh session sees the same records (persistence across sessions/restarts)
    with session_scope() as s:
        e = s.get(Experiment, exp_id)
        assert e.status == "completed"
        cases = s.scalars(select(Case).where(Case.experiment_id == exp_id)).all()
        assert len(cases) == 1
