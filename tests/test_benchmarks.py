"""Benchmark engine: documented metrics, consistency, and reproducibility."""
from app.benchmarks.runner import compute_metrics
from tests.conftest import default_policy_id, make_target


class FakeCase:
    def __init__(self, scenario_key, status, outcome):
        self.scenario_key = scenario_key
        self.status = status
        self.outcome = outcome


def test_metrics_have_documented_formulas():
    cases = [
        FakeCase("inj.direct.override", "model_violation",
                 {"expected_outcome": "refuse", "category": "injection",
                  "prohibited_tools": [], "approval_required": []}),
        FakeCase("inj.direct.override", "pass",
                 {"expected_outcome": "refuse", "category": "injection",
                  "prohibited_tools": [], "approval_required": []}),
        FakeCase("policy.benign_overrefusal", "pass",
                 {"expected_outcome": "comply", "category": "policy",
                  "prohibited_tools": [], "approval_required": []}),
    ]
    m = compute_metrics(cases)
    assert m["cases_total"] == 3
    assert m["coverage_rate"] == 1.0
    mi = m["metrics"]
    # 1 violation / 3 evaluated
    assert mi["policy_violation_rate"]["value"] == round(1 / 3, 4)
    assert mi["policy_violation_rate"]["numerator"] == 1
    assert mi["policy_violation_rate"]["denominator"] == 3
    assert mi["benign_task_completion_rate"]["value"] == 1.0
    assert mi["false_refusal_rate"]["value"] == 0.0
    assert mi["prompt_injection_success_rate"]["value"] == 0.5
    assert all("definition" in v for v in mi.values())
    assert m["limitations"]


def test_infra_errors_excluded_from_violation_rates():
    cases = [
        FakeCase("inj.direct.override", "infra_error", {"category": "injection"}),
        FakeCase("jail.persona_pressure", "pass",
                 {"expected_outcome": "refuse", "category": "jailbreak"}),
    ]
    m = compute_metrics(cases)
    assert m["metrics"]["policy_violation_rate"]["value"] == 0.0
    assert m["metrics"]["infra_error_rate"]["value"] == 0.5


def test_benchmark_via_api(client, researcher_headers, admin_headers, project_id):
    tid = make_target(client, researcher_headers, project_id, "bench-target", "leak_canary")
    r = client.post("/api/v1/benchmarks/run", headers=researcher_headers, json={
        "project_id": project_id, "target_id": tid,
        "policy_id": default_policy_id(client, admin_headers),
        "suite_key": "safety-core",
        "authorization": {"authorized_by": "test-suite", "acknowledged": True, "scope": "tests"},
        "config": {}})
    assert r.status_code == 200, r.text
    metrics = r.json()["metrics"]["metrics"]
    # leaky mock must show non-zero injection success on this suite
    assert metrics["prompt_injection_success_rate"]["value"] > 0
    # benchmark listed with identical persisted metrics
    runs = client.get("/api/v1/benchmarks", headers=researcher_headers).json()
    assert runs and runs[0]["metrics"] == r.json()["metrics"]


def test_regression_pack_resolves_from_confirmed_findings(client, researcher_headers, admin_headers,
                                                          project_id):
    tid = make_target(client, researcher_headers, project_id, "regress-target", "leak_canary")
    client.post("/api/v1/benchmarks/run", headers=researcher_headers, json={
        "project_id": project_id, "target_id": tid,
        "policy_id": default_policy_id(client, admin_headers),
        "suite_key": "safety-core",
        "authorization": {"authorized_by": "t", "acknowledged": True}, "config": {}})
    r = client.get("/api/v1/scenarios", headers=researcher_headers,
                   params={"category": "regression"}).json()
    assert any(s["source"] == "regression" for s in r)
