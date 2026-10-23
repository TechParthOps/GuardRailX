"""Bootstrap: admin user, default policy, demo project with a mock target,
and one real demo experiment executed against the deterministic mock adapter
(explicitly labeled is_demo). Dashboard data therefore reflects stored results.
"""
from __future__ import annotations

import logging
import secrets

from sqlalchemy import select

from app.auth import service as authsvc
from app.config import get_settings
from app.db import session_scope
from app.experiments import orchestrator as orch
from app.models import Policy, Project, Target, new_id
from app.policy.engine import DEFAULT_POLICY_DOCUMENT

log = logging.getLogger("guardrailx.seed")


def bootstrap() -> dict:
    settings = get_settings()
    admin_email = settings.admin_email

    with session_scope() as s:
        admin = s.scalar(select(authsvc.User).where(authsvc.User.email == admin_email))
        if not admin:
            password = settings.admin_password or ("gx-" + secrets.token_urlsafe(12))
            admin = authsvc.create_user(admin_email, password, role="admin")
            if not settings.admin_password:
                pw_file = settings.data_dir / "initial_admin_password.txt"
                pw_file.write_text(password, encoding="utf-8")
                try:
                    import os
                    os.chmod(pw_file, 0o600)
                except OSError:
                    pass
                log.warning("initial admin password written to %s (remove after first login)", pw_file)
            admin_created = True
        else:
            admin_created = False

        if not s.scalar(select(Policy).where(Policy.name == "default")):
            pol = Policy(id=new_id("pol"), name="default", version=1,
                         document=DEFAULT_POLICY_DOCUMENT, active=True, created_by=admin.id)
            s.add(pol)
            s.flush()
            orch.load_policies_for_run(pol.id, pol.version, pol.document)
        policy = s.scalar(select(Policy).where(Policy.name == "default", Policy.active == True))  # noqa: E712

        # register builtin scenario library (idempotent)
        from app.models import Scenario as ScenarioModel
        from app.scenarios.library import get_builtin_scenarios
        for scen in get_builtin_scenarios():
            s.merge(ScenarioModel(key=scen["key"], category=scen["category"], title=scen["title"],
                                  description=scen["description"], template=scen["template"],
                                  risk=scen["risk"], source="builtin"))

        demo = s.scalar(select(Project).where(Project.name == "Demo (mock target)"))
        if not demo:
            demo = Project(id=new_id("prj"), name="Demo (mock target)",
                           description="Labeled demo project using the deterministic mock adapter. "
                                       "All results shown here come from real executed experiment records.",
                           owner_id=admin.id, is_demo=True)
            s.add(demo)
            s.flush()
        project_id = demo.id

        mock_target = s.scalar(select(Target).where(Target.project_id == demo.id,
                                                    Target.name == "mock-leaky-assistant"))
        if not mock_target:
            mock_target = Target(id=new_id("tgt"), project_id=demo.id,
                                 name="mock-leaky-assistant", adapter_name="mock",
                                 model="mock-model",
                                 config={"model": "mock-model", "behavior": "leak_canary"},
                                 status="operational",
                                 last_health={"ok": True, "detail": "deterministic mock adapter",
                                              "latency_ms": 0})
            s.add(mock_target)
            s.flush()
        target_id = mock_target.id
        policy_id = policy.id

    orch.load_policies_for_run(policy_id, 1, DEFAULT_POLICY_DOCUMENT)
    return {"admin_created": admin_created, "admin_email": admin_email,
            "project_id": project_id, "target_id": target_id, "policy_id": policy_id}


async def run_demo_experiment(bootstrap_info: dict) -> str | None:
    """Execute one real experiment against the mock adapter (labeled demo data)."""
    from app.models import Experiment
    from sqlalchemy import select as _select
    with session_scope() as s:
        existing = s.scalar(_select(Experiment).where(Experiment.title == "Demo: canary leak evaluation"))
        if existing:
            return existing.id
    try:
        result = orch.create_experiment(
            project_id=bootstrap_info["project_id"],
            target_id=bootstrap_info["target_id"],
            policy_id=bootstrap_info["policy_id"],
            scenario_keys=["inj.direct.override", "inj.indirect.retrieved_doc",
                           "tool.unauthorized_delete", "tool.egress_no_approval",
                           "tool.sandbox_escape", "rag.poisoned_corpus",
                           "policy.benign_overrefusal"],
            title="Demo: canary leak evaluation",
            authorization={"authorized_by": "system-bootstrap", "acknowledged": True,
                           "scope": "local demo project with deterministic mock adapter"},
            config={"replays": 1, "gateway_mode": "simulated"},
            created_by="system-bootstrap")
    except (PermissionError, ValueError) as exc:
        log.warning("demo experiment not created: %s", exc)
        return None
    await orch.run_experiment(result["id"])
    return result["id"]
