"""Module L — versioned REST API (v1).

All mutating endpoints require authentication and RBAC. Privileged admin
operations (policies activation, emergency stop, users) require 'admin'.
Rate limiting and secret redaction are applied at the app level.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select

from app.api import schemas as S
from app.auth import service as authsvc
from app.auth.service import Principal, require_admin, require_researcher, require_viewer
from app.benchmarks import runner as bench
from app.config import get_settings
from app.db import session_scope
from app.experiments import orchestrator as orch
from app.experiments import redteam as rt
from app.experiments.findings import verify_finding
from app.models import (Approval, BenchmarkRun, Case, EventRecord, Experiment,
                        Finding, Policy, Project, Regression, Scenario, Target,
                        User, new_id, utcnow)
from app.observability.bus import bus
from app.observability.events import event_to_dict, record_event
from app.observability.redaction import redact_obj
from app.policy.engine import policy_engine, DEFAULT_POLICY_DOCUMENT, validate_policy_document, document_hash
from app.scenarios.library import CATEGORIES, get_builtin_scenarios
from app.tools import builtin

log = logging.getLogger("guardrailx.api")
router = APIRouter(prefix="/api/v1")


# ------------------------------------------------------------------- health

@router.get("/health", tags=["system"])
def health() -> dict[str, Any]:
    return {"status": "ok", "app": get_settings().app_name, "environment": get_settings().environment}


@router.get("/ready", tags=["system"])
def ready() -> dict[str, Any]:
    from app.db import engine
    db_ok = False
    try:
        from sqlalchemy import text as _t
        with engine.connect() as conn:
            conn.execute(_t("SELECT 1"))
        db_ok = True
    except Exception:
        pass
    return {"database": db_ok, "emergency_stop": orch.emergency_stop_active(),
            "experiments_running": len(orch.EXPERIMENT_TASKS)}


# --------------------------------------------------------------------- auth

@router.post("/auth/login", tags=["auth"])
def login(body: S.LoginRequest) -> dict[str, Any]:
    user, token = authsvc.authenticate(body.email, body.password)
    if not user:
        authsvc.audit(body.email, "auth.login_failed")
        raise HTTPException(401, "invalid credentials")
    authsvc.audit(user.email, "auth.login")
    return {"access_token": token, "token_type": "bearer", "role": user.role, "email": user.email}


@router.post("/auth/logout", tags=["auth"])
def logout(principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
    with session_scope() as s:
        at = s.get(authsvc.AuthToken, principal.token.id)
        if at:
            at.revoked = True
    authsvc.audit(principal.email, "auth.logout")
    return {"ok": True}


@router.get("/auth/me", tags=["auth"])
def me(principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
    return {"email": principal.email, "role": principal.role, "user_id": principal.id}


@router.post("/auth/users", tags=["auth"])
def create_user(body: S.CreateUserRequest, principal: Principal = Depends(require_admin)) -> dict[str, Any]:
    try:
        u = authsvc.create_user(body.email, body.password, body.role)
    except ValueError:
        raise HTTPException(409, "user already exists")
    authsvc.audit(principal.email, "user.created", "user", u.id, {"role": body.role})
    return {"id": u.id, "email": u.email, "role": u.role}


@router.post("/auth/api-keys", tags=["auth"])
def create_api_key(body: S.ApiKeyRequest, principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
    if body.role and principal.role != "admin":
        raise HTTPException(403, "only admins may mint keys with elevated roles")
    token, at = authsvc.create_api_key(principal.user, body.name, body.role)
    authsvc.audit(principal.email, "api_key.created", "api_key", at.id, {"name": body.name, "role": at.role})
    return {"api_key": token, "prefix": at.prefix, "role": at.role,
            "note": "store securely; it is shown only once and stored only as a hash"}


@router.get("/auth/api-keys", tags=["auth"])
def list_api_keys(principal: Principal = Depends(require_viewer)) -> list[dict[str, Any]]:
    with session_scope() as s:
        rows = s.scalars(select(authsvc.AuthToken).where(
            authsvc.AuthToken.kind == "api_key", authsvc.AuthToken.user_id == principal.id,
            authsvc.AuthToken.revoked == False)).all()  # noqa: E712
        return [{"id": r.id, "name": r.name, "prefix": r.prefix, "role": r.role,
                 "created_at": str(r.created_at)} for r in rows]


@router.delete("/auth/api-keys/{key_id}", tags=["auth"])
def revoke_api_key(key_id: str, principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
    with session_scope() as s:
        at = s.get(authsvc.AuthToken, key_id)
        if not at or at.kind != "api_key" or (at.user_id != principal.id and principal.role != "admin"):
            raise HTTPException(404, "api key not found")
        at.revoked = True
    authsvc.audit(principal.email, "api_key.revoked", "api_key", key_id)
    return {"ok": True}


# ----------------------------------------------------------------- projects

@router.get("/projects", tags=["projects"])
def list_projects(principal: Principal = Depends(require_viewer)) -> list[dict[str, Any]]:
    with session_scope() as s:
        rows = s.scalars(select(Project)).all()
        return [{"id": p.id, "name": p.name, "description": p.description,
                 "is_demo": p.is_demo, "owner_id": p.owner_id} for p in rows]


@router.post("/projects", tags=["projects"])
def create_project(body: S.ProjectRequest, principal: Principal = Depends(require_researcher)) -> dict[str, Any]:
    with session_scope() as s:
        if s.scalar(select(Project).where(Project.name == body.name)):
            raise HTTPException(409, "project name exists")
        p = Project(id=new_id("prj"), name=body.name, description=body.description, owner_id=principal.id)
        s.add(p)
        s.flush()
        authsvc.audit(principal.email, "project.created", "project", p.id, session=s)
        return {"id": p.id, "name": p.name}


# ----------------------------------------------------------------- targets

@router.get("/adapters", tags=["targets"])
def list_adapters(principal: Principal = Depends(require_viewer)) -> list[dict[str, Any]]:
    from app.adapters.registry import registry
    return registry.list()


@router.get("/targets", tags=["targets"])
def list_targets(project_id: str | None = None, principal: Principal = Depends(require_viewer)) -> list[dict[str, Any]]:
    with session_scope() as s:
        q = select(Target)
        if project_id:
            q = q.where(Target.project_id == project_id)
        rows = s.scalars(q).all()
        return [{"id": t.id, "project_id": t.project_id, "name": t.name, "adapter_name": t.adapter_name,
                 "model": t.model, "status": t.status, "last_health": t.last_health,
                 "config": t.config, "is_demo": _project_is_demo(s, t.project_id)} for t in rows]


def _project_is_demo(s, project_id: str) -> bool:
    p = s.get(Project, project_id)
    return bool(p and p.is_demo)


@router.post("/targets", tags=["targets"])
def create_target(body: S.TargetRequest, principal: Principal = Depends(require_researcher)) -> dict[str, Any]:
    from app.adapters.registry import registry
    try:
        adapter = registry.get(body.adapter_name)
    except KeyError as exc:
        raise HTTPException(400, str(exc))
    ok, detail = adapter.validate_config(body.config | ({"model": body.model} if body.model else {}))
    if not ok:
        raise HTTPException(400, f"adapter config invalid: {detail}")
    with session_scope() as s:
        if not s.get(Project, body.project_id):
            raise HTTPException(404, "project not found")
        if s.scalar(select(Target).where(Target.project_id == body.project_id, Target.name == body.name)):
            raise HTTPException(409, "target name exists in project")
        t = Target(id=new_id("tgt"), project_id=body.project_id, name=body.name,
                   adapter_name=body.adapter_name, model=body.model, config=body.config,
                   status="unverified")
        s.add(t)
        s.flush()
        authsvc.audit(principal.email, "target.created", "target", t.id, session=s,
                      detail={"adapter": body.adapter_name, "model": body.model})
        return {"id": t.id, "name": t.name, "status": t.status}


@router.post("/targets/{target_id}/test-connection", tags=["targets"])
def test_connection(target_id: str, principal: Principal = Depends(require_researcher)) -> dict[str, Any]:
    """REAL connection test; target becomes operational only on success."""
    from app.adapters.registry import registry
    with session_scope() as s:
        t = s.get(Target, target_id)
        if not t:
            raise HTTPException(404, "target not found")
        result = registry.test_connection(t.adapter_name, t.config | ({"model": t.model} if t.model else {}))
        t.status = "operational" if result.ok else "failed"
        t.last_health = {"ok": result.ok, "detail": result.detail, "latency_ms": result.latency_ms,
                         "tested_at": str(utcnow())}
        record_event(s, experiment_id=None, type_="target.health", actor=principal.email,
                     payload={"target": t.name, "adapter": t.adapter_name,
                              "ok": result.ok, "detail": result.detail})
        authsvc.audit(principal.email, "target.connection_tested", "target", t.id, session=s,
                      detail={"ok": result.ok, "detail": result.detail})
        return {"target_id": t.id, "status": t.status, "health": t.last_health}


@router.delete("/targets/{target_id}", tags=["targets"])
def delete_target(target_id: str, principal: Principal = Depends(require_researcher)) -> dict[str, Any]:
    with session_scope() as s:
        t = s.get(Target, target_id)
        if not t:
            raise HTTPException(404, "target not found")
        linked = s.query(Experiment).filter(Experiment.target_id == target_id).count()
        if linked:
            raise HTTPException(409,
                                f"target has {linked} linked experiments; "
                                "targets referenced by experiment records are retained for evidence integrity")
        s.delete(t)
    authsvc.audit(principal.email, "target.deleted", "target", target_id)
    return {"ok": True}


# ---------------------------------------------------------------- policies

@router.get("/policies", tags=["policy"])
def list_policies(principal: Principal = Depends(require_viewer)) -> list[dict[str, Any]]:
    with session_scope() as s:
        rows = s.scalars(select(Policy).order_by(Policy.name, Policy.version.desc())).all()
        return [{"id": p.id, "name": p.name, "version": p.version, "active": p.active,
                 "project_id": p.project_id, "document": p.document,
                 "document_hash": document_hash(p.document)} for p in rows]


@router.post("/policies", tags=["policy"])
def create_policy(body: S.PolicyRequest, principal: Principal = Depends(require_admin)) -> dict[str, Any]:
    ok, detail = validate_policy_document(body.document)
    if not ok:
        raise HTTPException(400, f"invalid policy: {detail}")
    with session_scope() as s:
        prev = s.scalars(select(Policy).where(Policy.name == body.name)).all()
        version = max((p.version for p in prev), default=0) + 1
        p = Policy(id=new_id("pol"), project_id=body.project_id, name=body.name,
                   version=version, document=body.document, active=False, created_by=principal.id)
        s.add(p)
        s.flush()
        policy_engine.load(p.id, version, body.document)
        authsvc.audit(principal.email, "policy.created", "policy", p.id, {"version": version}, session=s)
        return {"id": p.id, "name": p.name, "version": version, "active": p.active}


@router.post("/policies/{policy_id}/activate", tags=["policy"])
def activate_policy(policy_id: str, principal: Principal = Depends(require_admin)) -> dict[str, Any]:
    with session_scope() as s:
        p = s.get(Policy, policy_id)
        if not p:
            raise HTTPException(404, "policy not found")
        s.query(Policy).filter(Policy.name == p.name).update({Policy.active: False})
        p.active = True
        policy_engine.load(p.id, p.version, p.document)
        authsvc.audit(principal.email, "policy.activated", "policy", p.id, {"version": p.version}, session=s)
        return {"id": p.id, "active": True, "version": p.version}


@router.post("/policies/evaluate", tags=["policy"])
def evaluate_policy(body: S.PolicyEvaluateRequest, principal: Principal = Depends(require_researcher)) -> dict[str, Any]:
    """Dry-run a policy decision without executing anything."""
    with session_scope() as s:
        p = s.get(Policy, body.policy_id)
        if not p:
            raise HTTPException(404, "policy not found")
        policy_engine.load(p.id, p.version, p.document)
        spec = builtin.TOOLS.get(body.tool_name)
        risk = spec.risk if spec else 100
        resource = orch.builtin_tool_schema(body.tool_name).get("name", "")
        d = policy_engine.evaluate(p.id, p.version, tool_name=body.tool_name,
                                   action_type="tool_call", risk=risk)
        return {"decision": d.to_dict(), "tool_registered": spec is not None, "tool_risk": risk}


@router.get("/policies/{policy_id}/conflicts", tags=["policy"])
def policy_conflicts(policy_id: str, principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
    with session_scope() as s:
        p = s.get(Policy, policy_id)
        if not p:
            raise HTTPException(404, "policy not found")
        policy_engine.load(p.id, p.version, p.document)
        return {"conflicts": policy_engine.explain_conflicts(p.id, p.version)}


# --------------------------------------------------------------- scenarios

@router.get("/scenarios", tags=["scenarios"])
def list_scenarios(category: str | None = None, principal: Principal = Depends(require_viewer)) -> list[dict[str, Any]]:
    with session_scope() as s:
        q = select(Scenario)
        if category:
            q = q.where(Scenario.category == category)
        rows = s.scalars(q).all()
        return [{"key": r.key, "category": r.category, "title": r.title, "description": r.description,
                 "risk": r.risk, "source": r.source, "template": r.template} for r in rows]


@router.get("/scenarios/categories", tags=["scenarios"])
def scenario_categories(principal: Principal = Depends(require_viewer)) -> dict[str, str]:
    return CATEGORIES


@router.post("/scenarios", tags=["scenarios"])
def create_custom_scenario(body: S.CustomScenarioRequest, principal: Principal = Depends(require_researcher)) -> dict[str, Any]:
    tpl = body.template
    if "messages" not in tpl or "expected" not in tpl:
        raise HTTPException(400, "template requires 'messages' and 'expected' (with outcome)")
    if tpl.get("expected", {}).get("outcome") not in ("refuse", "comply"):
        raise HTTPException(400, "expected.outcome must be 'refuse' or 'comply'")
    with session_scope() as s:
        if s.get(Scenario, body.key):
            raise HTTPException(409, "scenario key exists")
        scen = Scenario(key=body.key, category=body.category, title=body.title,
                        description=body.description, template=tpl, risk=body.risk, source="custom")
        s.add(scen)
        authsvc.audit(principal.email, "scenario.created", "scenario", body.key, session=s)
        return {"key": scen.key}


# ------------------------------------------------------------- experiments

@router.get("/experiments", tags=["experiments"])
def list_experiments(principal: Principal = Depends(require_viewer)) -> list[dict[str, Any]]:
    with session_scope() as s:
        rows = s.scalars(select(Experiment).order_by(Experiment.created_at.desc())).all()
        return [_exp_dict(e) for e in rows]


def _exp_dict(e: Experiment) -> dict[str, Any]:
    return {"id": e.id, "project_id": e.project_id, "target_id": e.target_id, "policy_id": e.policy_id,
            "title": e.title, "status": e.status, "scenario_keys": e.scenario_keys,
            "stats": e.stats, "started_at": str(e.started_at or ""), "finished_at": str(e.finished_at or ""),
            "config": e.config, "adapter_version": e.adapter_version, "policy_version": e.policy_version,
            "target_model": e.target_model, "error": e.error}


@router.post("/experiments", tags=["experiments"])
def create_experiment(body: S.ExperimentRequest, principal: Principal = Depends(require_researcher)) -> dict[str, Any]:
    settings = get_settings()
    cfg = body.config or {}
    cfg.setdefault("replays", settings.case_replays)
    if len(body.scenario_keys) * int(cfg.get("replays", 1)) > settings.max_cases_per_experiment:
        raise HTTPException(400, f"cases exceed limit ({settings.max_cases_per_experiment})")
    try:
        result = orch.create_experiment(
            project_id=body.project_id, target_id=body.target_id, policy_id=body.policy_id,
            scenario_keys=body.scenario_keys, title=body.title, authorization=body.authorization,
            config=cfg, created_by=principal.id)
    except RuntimeError as exc:
        raise HTTPException(423, str(exc))
    except PermissionError as exc:
        raise HTTPException(403, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    authsvc.audit(principal.email, "experiment.created", "experiment", result["id"],
                  detail={"scenarios": body.scenario_keys})
    return result


@router.post("/experiments/{experiment_id}/start", tags=["experiments"])
async def start_experiment(experiment_id: str, principal: Principal = Depends(require_researcher)) -> dict[str, Any]:
    if orch.emergency_stop_active():
        raise HTTPException(423, "emergency stop active")
    with session_scope() as s:
        exp = s.get(Experiment, experiment_id)
        if not exp:
            raise HTTPException(404, "experiment not found")
    task = asyncio.create_task(orch.run_experiment(experiment_id))
    return {"id": experiment_id, "started": True, "task": id(task)}


@router.get("/experiments/{experiment_id}", tags=["experiments"])
def get_experiment(experiment_id: str, principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
    with session_scope() as s:
        exp = s.get(Experiment, experiment_id)
        if not exp:
            raise HTTPException(404, "experiment not found")
        cases = s.scalars(select(Case).where(Case.experiment_id == experiment_id).order_by(Case.seq)).all()
        d = _exp_dict(exp)
        d["cases"] = [{"id": c.id, "seq": c.seq, "scenario_key": c.scenario_key, "replay": c.replay,
                       "status": c.status, "outcome": c.outcome, "trace_id": c.trace_id,
                       "finding_id": c.finding_id} for c in cases]
        return d


@router.post("/experiments/{experiment_id}/cancel", tags=["experiments"])
def cancel_experiment(experiment_id: str, principal: Principal = Depends(require_researcher)) -> dict[str, Any]:
    try:
        cancelled = orch.cancel_experiment(experiment_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    authsvc.audit(principal.email, "experiment.cancelled", "experiment", experiment_id)
    return {"id": experiment_id, "cancelled": cancelled}


@router.get("/experiments/{experiment_id}/events", tags=["experiments"])
def experiment_events(experiment_id: str, principal: Principal = Depends(require_viewer),
                      limit: int = Query(500, le=5000)) -> list[dict[str, Any]]:
    with session_scope() as s:
        rows = s.scalars(select(EventRecord).where(EventRecord.experiment_id == experiment_id)
                         .order_by(EventRecord.seq).limit(limit)).all()
        return [event_to_dict(e) for e in rows]


@router.get("/experiments/{experiment_id}/trace-analysis", tags=["experiments"])
def trace_analysis(experiment_id: str, principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
    with session_scope() as s:
        rows = s.scalars(select(EventRecord).where(EventRecord.experiment_id == experiment_id)
                         .order_by(EventRecord.seq)).all()
        return rt.trace_analysis_report([event_to_dict(e) for e in rows])


# ---------------------------------------------------------------- approvals

@router.get("/approvals/pending", tags=["approvals"])
def pending_approvals(principal: Principal = Depends(require_viewer)) -> list[dict[str, Any]]:
    with session_scope() as s:
        rows = s.scalars(select(Approval).where(Approval.status == "pending")).all()
        return [{"id": a.id, "experiment_id": a.experiment_id, "case_id": a.case_id,
                 "tool_name": a.tool_name, "arguments": a.arguments, "reason": a.reason,
                 "requested_at": str(a.created_at)} for a in rows]


@router.post("/approvals/{approval_id}/decide", tags=["approvals"])
def decide_approval(approval_id: str, body: S.ApproveRequest,
                    principal: Principal = Depends(require_admin)) -> dict[str, Any]:
    """Only admins may approve consequential actions (human approval gate)."""
    with session_scope() as s:
        a = s.get(Approval, approval_id)
        if not a:
            raise HTTPException(404, "approval not found")
        if a.status != "pending":
            raise HTTPException(409, f"approval already '{a.status}'")
        a.status = body.decision
        a.decided_by = principal.email
        a.decided_at = utcnow()
        a.reason = body.reason
        record_event(s, experiment_id=a.experiment_id, case_id=a.case_id,
                     type_="approval.decided", actor=principal.email,
                     payload={"approval_id": a.id, "decision": body.decision, "reason": body.reason})
        if body.decision == "approved":
            gw = _gateway_for_experiment(s, a.experiment_id)
            res = gw.execute_approved(s, a, a.experiment_id, a.case_id, None)
            authsvc.audit(principal.email, "approval.granted_executed", "approval", a.id, session=s,
                          detail={"tool": a.tool_name, "executed": res.executed})
            return {"approval_id": a.id, "decision": "approved", "executed": res.to_dict()}
        authsvc.audit(principal.email, "approval.denied", "approval", a.id, {"tool": a.tool_name}, session=s)
        return {"approval_id": a.id, "decision": "denied"}


def _gateway_for_experiment(s, experiment_id: str) -> orch.ToolGateway:
    from app.policy.engine import policy_engine
    exp = s.get(Experiment, experiment_id)
    ensure_loaded(policy_engine, exp.policy_id, exp.policy_version, s)
    return orch.ToolGateway(policy_engine, exp.policy_id, exp.policy_version,
                            get_settings().sandbox_dir,
                            mode=exp.config.get("gateway_mode", "simulated"),
                            dry_run=bool(exp.config.get("dry_run")))


def ensure_loaded(engine, policy_id: str, version: int, s) -> None:
    if (policy_id, version) in engine._cache:
        return
    p = s.get(Policy, policy_id)
    engine.load(policy_id, version, p.document)


# ---------------------------------------------------------------- findings

@router.get("/findings", tags=["findings"])
def list_findings(experiment_id: str | None = None, status: str | None = None,
                  severity: str | None = None, principal: Principal = Depends(require_viewer)) -> list[dict[str, Any]]:
    with session_scope() as s:
        q = select(Finding)
        if experiment_id:
            q = q.where(Finding.experiment_id == experiment_id)
        if status:
            q = q.where(Finding.status == status)
        if severity:
            q = q.where(Finding.severity == severity)
        rows = s.scalars(q.order_by(Finding.created_at.desc())).all()
        return [_finding_dict(f) for f in rows]


def _finding_dict(f: Finding) -> dict[str, Any]:
    return {"id": f.id, "experiment_id": f.experiment_id, "case_id": f.case_id,
            "target_id": f.target_id, "title": f.title, "category": f.category,
            "vuln_class": f.vuln_class, "severity": f.severity, "confidence": f.confidence,
            "status": f.status, "expected": f.expected, "observed": f.observed,
            "preconditions": f.preconditions, "impact": f.impact, "likelihood": f.likelihood,
            "limitations": f.limitations, "remediation": f.remediation,
            "evidence_event_ids": f.evidence_event_ids, "reproduction": f.reproduction,
            "failure_layer": f.failure_layer, "reproducible": f.reproducible,
            "created_at": str(f.created_at), "updated_at": str(f.updated_at)}


@router.get("/findings/{finding_id}", tags=["findings"])
def get_finding(finding_id: str, principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
    with session_scope() as s:
        f = s.get(Finding, finding_id)
        if not f:
            raise HTTPException(404, "finding not found")
        reg = s.scalar(select(Regression).where(Regression.finding_id == f.id))
        d = _finding_dict(f)
        d["regression_scenario_key"] = reg.scenario_key if reg else None
        return d


@router.post("/findings/{finding_id}/verify", tags=["findings"])
def verify(finding_id: str, principal: Principal = Depends(require_researcher)) -> dict[str, Any]:
    with session_scope() as s:
        f = s.get(Finding, finding_id)
        if not f:
            raise HTTPException(404, "finding not found")
        verify_finding(s, f)
        record_event(s, experiment_id=f.experiment_id, type_="finding.verified",
                     actor=principal.email, payload={"finding_id": f.id, "status": f.status})
        authsvc.audit(principal.email, "finding.verified", "finding", f.id, {"status": f.status}, session=s)
        return _finding_dict(f)


# ---------------------------------------------------------------- red team

@router.post("/redteam/variations", tags=["redteam"])
def create_variations(body: S.RedTeamRequest, principal: Principal = Depends(require_researcher)) -> dict[str, Any]:
    with session_scope() as s:
        keys = rt.register_variations(s, body.base_scenario_keys, body.variations_per_base, principal.id)
    authsvc.audit(principal.email, "redteam.variations_created", "scenario", "", {"count": len(keys)})
    return {"variation_keys": keys, "note": "variations inherit the base scenario's expected contract; scope unchanged"}


@router.post("/redteam/remediation", tags=["redteam"])
def remediation(experiment_id: str, principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
    with session_scope() as s:
        rows = s.scalars(select(Finding).where(Finding.experiment_id == experiment_id)).all()
        plan = rt.remediation_plan([_finding_dict(f) for f in rows])
    return {"experiment_id": experiment_id, "plan": plan}


# --------------------------------------------------------------- benchmarks

@router.get("/benchmarks/suites", tags=["benchmarks"])
def benchmark_suites(principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
    return {"suites": bench.SUITES, "dynamic": ["regression-pack"]}


@router.post("/benchmarks/run", tags=["benchmarks"])
async def run_benchmark(body: S.BenchmarkRequest, principal: Principal = Depends(require_researcher)) -> dict[str, Any]:
    try:
        with session_scope() as s:
            scenario_keys = bench.resolve_suite_scenarios(s, body.suite_key)
        if not scenario_keys:
            raise HTTPException(400, f"suite '{body.suite_key}' has no scenarios")
        result = orch.create_experiment(
            project_id=body.project_id, target_id=body.target_id, policy_id=body.policy_id,
            scenario_keys=scenario_keys, title=f"Benchmark suite '{body.suite_key}'",
            authorization=body.authorization, config=body.config | {"replays": 1},
            created_by=principal.id)
    except PermissionError as exc:
        raise HTTPException(403, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    run = BenchmarkRun(id=new_id("bmk"), suite_key=body.suite_key, target_id=body.target_id,
                       project_id=body.project_id, policy_id=body.policy_id,
                       config=body.config, status="running", experiment_id=result["id"],
                       started_at=utcnow())
    with session_scope() as s:
        s.add(run)
        s.flush()
        run_id = run.id

    await orch.run_experiment(result["id"])

    with session_scope() as s:
        cases = s.scalars(select(Case).where(Case.experiment_id == result["id"])).all()
        metrics = bench.compute_metrics(cases)
        run_row = s.get(BenchmarkRun, run_id)
        run_row.status = "completed"
        run_row.metrics = metrics
        run_row.finished_at = utcnow()
        authsvc.audit(principal.email, "benchmark.completed", "benchmark", run_id, session=s,
                      detail={"suite": body.suite_key})
        return {"benchmark_id": run_id, "experiment_id": result["id"], "metrics": metrics}


@router.get("/benchmarks", tags=["benchmarks"])
def list_benchmarks(principal: Principal = Depends(require_viewer)) -> list[dict[str, Any]]:
    with session_scope() as s:
        rows = s.scalars(select(BenchmarkRun).order_by(BenchmarkRun.created_at.desc())).all()
        return [{"id": b.id, "suite_key": b.suite_key, "target_id": b.target_id,
                 "status": b.status, "metrics": b.metrics, "experiment_id": b.experiment_id,
                 "started_at": str(b.started_at or ""), "finished_at": str(b.finished_at or "")} for b in rows]


# ------------------------------------------------------------------- events

@router.get("/events", tags=["observability"])
def search_events(experiment_id: str | None = None, type_: str | None = Query(None, alias="type"),
                  level: str | None = None, limit: int = Query(200, le=2000),
                  principal: Principal = Depends(require_viewer)) -> list[dict[str, Any]]:
    with session_scope() as s:
        q = select(EventRecord).order_by(EventRecord.created_at.desc()).limit(limit)
        if experiment_id:
            q = q.where(EventRecord.experiment_id == experiment_id)
        if type_:
            q = q.where(EventRecord.type == type_)
        if level:
            q = q.where(EventRecord.level == level)
        rows = s.scalars(q).all()
        return [event_to_dict(e) for e in rows]


@router.get("/events/stream", tags=["observability"])
async def event_stream(experiment_id: str | None = None,
                       principal: Principal = Depends(require_viewer)) -> StreamingResponse:
    async def gen():
        q = await bus.subscribe(experiment_id)
        try:
            yield ": connected\n\n"
            while True:
                ev = await q.get()
                yield f"data: {json.dumps(redact_obj(ev), default=str)}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            await bus.unsubscribe(q, experiment_id)
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# -------------------------------------------------------------------- admin

@router.post("/admin/emergency-stop", tags=["admin"])
def emergency_stop(body: dict[str, Any], principal: Principal = Depends(require_admin)) -> dict[str, Any]:
    active = bool(body.get("active", True))
    orch.emergency_stop(active)
    authsvc.audit(principal.email, "admin.emergency_stop", "system", "", {"active": active})
    return {"emergency_stop": active}


@router.get("/admin/audit", tags=["admin"])
def audit_log(limit: int = Query(200, le=2000), principal: Principal = Depends(require_admin)) -> list[dict[str, Any]]:
    from app.models import AuditEvent
    with session_scope() as s:
        rows = s.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)).all()
        return [{"id": a.id, "actor": a.actor, "action": a.action, "object_type": a.object_type,
                 "object_id": a.object_id, "detail": a.detail, "created_at": str(a.created_at)} for a in rows]


@router.get("/admin/stats", tags=["admin"])
def stats(principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
    with session_scope() as s:
        return {
            "targets": s.query(Target).count(),
            "targets_operational": s.query(Target).filter(Target.status == "operational").count(),
            "experiments": s.query(Experiment).count(),
            "experiments_running": len(orch.EXPERIMENT_TASKS),
            "findings_confirmed": s.query(Finding).filter(
                Finding.status.in_(["confirmed", "remediation_proposed", "regression_tested", "closed"])).count(),
            "findings_total": s.query(Finding).count(),
            "findings_by_severity": _count_by(s, Finding, Finding.severity),
            "findings_by_status": _count_by(s, Finding, Finding.status),
            "benchmarks": s.query(BenchmarkRun).count(),
            "approvals_pending": s.query(Approval).filter(Approval.status == "pending").count(),
            "emergency_stop": orch.emergency_stop_active(),
        }


def _count_by(s, model, col) -> dict[str, int]:
    from collections import Counter
    return dict(Counter(x[0] for x in s.query(col).all()))


@router.get("/admin/events/severity", tags=["admin"])
def enforcement_failures(principal: Principal = Depends(require_viewer)) -> list[dict[str, Any]]:
    with session_scope() as s:
        rows = s.scalars(select(EventRecord).where(
            EventRecord.type.in_(["tool.blocked", "tool.executed", "approval.requested", "finding.discovered"]))
            .order_by(EventRecord.created_at.desc()).limit(100)).all()
        return [event_to_dict(e) for e in rows]
