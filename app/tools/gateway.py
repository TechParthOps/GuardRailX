"""Policy Enforcement Point (PEP) — the single gateway through which every
proposed tool action must pass. Fail-closed by construction:

  1. Unknown tool            -> blocked (never executed).
  2. Policy deny             -> blocked.
  3. Policy require_approval -> action is held as a pending Approval record;
                                it does NOT execute until a human approves.
  4. Policy allow            -> executes via the sandboxed executor
                                (simulated mode unless explicitly enabled).
  5. Any internal error      -> blocked (never fails open).

The gateway records an enforcement event for every evaluation so traces can
be reconstructed (Module I) and enforcement failures become findings.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.models import Approval, new_id
from app.observability.events import record_event
from app.policy.engine import Decision, PolicyEngine
from app.tools import builtin

log = logging.getLogger("guardrailx.gateway")


@dataclass
class GatewayResult:
    action: str                    # executed | blocked | pending_approval | dry_run
    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    decision: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] = field(default_factory=dict)
    approval_id: str | None = None
    blocked_reason: str = ""

    @property
    def executed(self) -> bool:
        return self.action == "executed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action, "tool_name": self.tool_name, "arguments": self.arguments,
            "decision": self.decision, "result": self.result, "approval_id": self.approval_id,
            "blocked_reason": self.blocked_reason, "executed": self.executed,
        }


class ToolGateway:
    def __init__(self, engine: PolicyEngine, policy_id: str, policy_version: int,
                 sandbox_dir: Path, *, mode: str = "simulated", dry_run: bool = False):
        self.engine = engine
        self.policy_id = policy_id
        self.policy_version = policy_version
        self.sandbox_dir = sandbox_dir
        self.mode = mode          # 'simulated' or 'real' (real only affects read-only sandbox fs)
        self.dry_run = dry_run    # research dry-run: decide, never execute

    # ------------------------------------------------------------------

    def evaluate_only(self, session: Session, *, tool_name: str, arguments: dict[str, Any],
                      experiment_id: str | None, case_id: str | None, trace_id: str | None,
                      actor: str = "model") -> GatewayResult:
        """Dry-run: produce the decision without executing anything."""
        decision = self._decide(tool_name, arguments)
        record_event(session, experiment_id=experiment_id, case_id=case_id, trace_id=trace_id,
                     type_="policy.decision", actor="gateway", payload={
                         "tool": tool_name, "arguments": arguments, "dry_run": True,
                         "decision": decision.to_dict()})
        action = {"allow": "dry_run", "deny": "blocked", "require_approval": "dry_run"}[decision.effect]
        reason = "dry-run mode: decision recorded, tool not executed" if action == "dry_run" else "dry-run mode: policy would deny"
        return GatewayResult(action=action, tool_name=tool_name, arguments=arguments,
                             decision=decision.to_dict(), blocked_reason=reason if action == "blocked" else "")

    def execute(self, session: Session, *, tool_call: dict[str, Any],
                experiment_id: str | None, case_id: str | None, trace_id: str | None,
                actor: str = "model") -> GatewayResult:
        tool_name = str(tool_call.get("name", ""))
        arguments = tool_call.get("arguments") or {}

        record_event(session, experiment_id=experiment_id, case_id=case_id, trace_id=trace_id,
                     type_="tool.proposed", actor=actor,
                     payload={"tool": tool_name, "arguments": arguments})

        spec = builtin.TOOLS.get(tool_name)
        if spec is None:
            res = GatewayResult(action="blocked", tool_name=tool_name, arguments=arguments,
                                blocked_reason=f"tool '{tool_name}' is not registered (fail-closed)")
            self._record_block(session, experiment_id, case_id, trace_id, res, "unregistered-tool")
            return res

        decision = self._decide(tool_name, arguments)
        record_event(session, experiment_id=experiment_id, case_id=case_id, trace_id=trace_id,
                     type_="policy.decision", actor="gateway",
                     payload={"tool": tool_name, "arguments": arguments, "decision": decision.to_dict()})

        if decision.effect == "deny":
            res = GatewayResult(action="blocked", tool_name=tool_name, arguments=arguments,
                                decision=decision.to_dict(), blocked_reason=decision.explanation)
            self._record_block(session, experiment_id, case_id, trace_id, res, "policy-deny")
            return res

        if decision.effect == "require_approval":
            approval = Approval(
                id=new_id("apr"), experiment_id=experiment_id or "standalone", case_id=case_id,
                tool_name=tool_name, arguments=arguments, status="pending", requested_by=actor,
                reason=decision.explanation,
            )
            session.add(approval)
            session.flush()
            record_event(session, experiment_id=experiment_id, case_id=case_id, trace_id=trace_id,
                         type_="approval.requested", actor="gateway",
                         payload={"tool": tool_name, "arguments": arguments, "approval_id": approval.id,
                                  "reason": decision.explanation})
            return GatewayResult(action="pending_approval", tool_name=tool_name, arguments=arguments,
                                 decision=decision.to_dict(), approval_id=approval.id)

        # effect == allow
        if self.dry_run:
            record_event(session, experiment_id=experiment_id, case_id=case_id, trace_id=trace_id,
                         type_="tool.dry_run", actor="gateway",
                         payload={"tool": tool_name, "arguments": arguments,
                                  "note": "dry-run: execution suppressed"})
            return GatewayResult(action="dry_run", tool_name=tool_name, arguments=arguments,
                                 decision=decision.to_dict())

        try:
            result = builtin.execute_tool(tool_name, arguments, self.sandbox_dir, mode=self.mode)
        except Exception as exc:  # fail-closed: executor crash must never look like success
            log.warning("tool executor error", exc_info=True)
            result = {"ok": False, "error": f"executor error: {type(exc).__name__}", "mode": "none"}
        if result.get("mode") == "blocked":
            # executor-level containment refusal (e.g. sandbox escape)
            res = GatewayResult(action="blocked", tool_name=tool_name, arguments=arguments,
                                decision=decision.to_dict(), result=result,
                                blocked_reason=str(result.get("error", "blocked by executor containment")))
            self._record_block(session, experiment_id, case_id, trace_id, res, "executor-containment")
            return res
        record_event(session, experiment_id=experiment_id, case_id=case_id, trace_id=trace_id,
                     type_="tool.executed", actor="gateway",
                     payload={"tool": tool_name, "arguments": arguments, "result": result})
        return GatewayResult(action="executed", tool_name=tool_name, arguments=arguments,
                             decision=decision.to_dict(), result=result)

    def execute_approved(self, session: Session, approval: Approval,
                         experiment_id: str | None, case_id: str | None,
                         trace_id: str | None) -> GatewayResult:
        """Execute an action whose approval was granted by a human."""
        try:
            result = builtin.execute_tool(approval.tool_name, approval.arguments,
                                          self.sandbox_dir, mode=self.mode)
        except Exception as exc:
            result = {"ok": False, "error": f"executor error: {type(exc).__name__}", "mode": "none"}
        record_event(session, experiment_id=experiment_id, case_id=case_id, trace_id=trace_id,
                     type_="tool.executed", actor="gateway",
                     payload={"tool": approval.tool_name, "arguments": approval.arguments,
                              "result": result, "approval_id": approval.id, "approved_by": approval.decided_by})
        return GatewayResult(action="executed", tool_name=approval.tool_name,
                             arguments=approval.arguments, result=result)

    # ------------------------------------------------------------------

    def _decide(self, tool_name: str, arguments: dict[str, Any]) -> Decision:
        spec = builtin.TOOLS.get(tool_name)
        risk = spec.risk if spec else 100
        resource = self._resource(tool_name, arguments)
        return self.engine.evaluate(self.policy_id, self.policy_version,
                                    tool_name=tool_name, action_type="tool_call",
                                    resource=resource, risk=risk)

    @staticmethod
    def _resource(tool_name: str, arguments: dict[str, Any]) -> str:
        if tool_name.startswith("sim_fs"):
            return "sandbox://" + str(arguments.get("path", "")).replace("\\", "/").lstrip("/")
        if tool_name.startswith("sim_net"):
            return "net://" + str(arguments.get("url", ""))
        return "tool://" + tool_name

    def _record_block(self, session: Session, experiment_id, case_id, trace_id,
                      res: GatewayResult, block_type: str) -> None:
        record_event(session, experiment_id=experiment_id, case_id=case_id, trace_id=trace_id,
                     type_="tool.blocked", actor="gateway", level="warning",
                     payload={"tool": res.tool_name, "arguments": res.arguments,
                              "block_type": block_type, "reason": res.blocked_reason,
                              "decision": res.decision})
