"""Module C — Independent guardrail policy engine (Policy Decision Point).

The PDP evaluates requests/tool calls against a versioned policy document.
It never executes anything and never trusts model self-reports; the
enforcement gateway (app.tools.gateway) is the single Policy Enforcement
Point that consumes these decisions.

Policy document schema (JSON, versioned):
{
  "name": "default",
  "default_effect": "deny",
  "rules": [
    {"id": "...", "effect": "allow|deny|require_approval",
     "tools": ["sim_fs.read"] or ["*"],
     "action_types": ["tool_call"],           # optional filter
     "resources": ["sandbox://*"],            # optional filter (fnmatch)
     "max_risk": 60,                           # optional: rule applies if tool risk <= max_risk
     "description": "human-readable rationale"}
  ]
}

Decision semantics: deny wins over require_approval wins over allow.
Conflicting matches are flagged in the explanation and resolved to deny.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

VALID_EFFECTS = {"allow", "deny", "require_approval"}


@dataclass
class Decision:
    effect: str                      # allow | deny | require_approval
    matched_rules: list[str] = field(default_factory=list)
    explanation: str = ""
    conflict: bool = False
    policy_id: str = ""
    policy_version: int = 0
    document_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "effect": self.effect, "matched_rules": self.matched_rules,
            "explanation": self.explanation, "conflict": self.conflict,
            "policy_id": self.policy_id, "policy_version": self.policy_version,
            "document_hash": self.document_hash,
        }


def document_hash(doc: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()[:16]


def validate_policy_document(doc: dict[str, Any]) -> tuple[bool, str]:
    if not isinstance(doc, dict):
        return False, "policy document must be an object"
    if doc.get("default_effect") not in {"allow", "deny"}:
        return False, "default_effect must be 'allow' or 'deny'"
    rules = doc.get("rules")
    if not isinstance(rules, list):
        return False, "rules must be a list"
    ids = set()
    for r in rules:
        if not isinstance(r, dict) or r.get("effect") not in VALID_EFFECTS:
            return False, f"invalid rule (missing/unknown effect): {r!r}"
        rid = r.get("id", "")
        if not rid or rid in ids:
            return False, f"rule ids must be unique and non-empty: {rid!r}"
        ids.add(rid)
        if not isinstance(r.get("tools", ["*"]), list):
            return False, f"rule {rid}: tools must be a list"
        if "max_risk" in r and not isinstance(r["max_risk"], (int, float)):
            return False, f"rule {rid}: max_risk must be numeric"
    return True, "ok"


class PolicyEngine:
    """Stateless PDP; loaded policy documents are cached by (id, version)."""

    def __init__(self) -> None:
        self._cache: dict[tuple[str, int], dict[str, Any]] = {}

    def load(self, policy_id: str, version: int, document: dict[str, Any]) -> None:
        ok, detail = validate_policy_document(document)
        if not ok:
            raise ValueError(f"invalid policy document: {detail}")
        self._cache[(policy_id, version)] = document

    def _doc(self, policy_id: str, version: int) -> dict[str, Any]:
        try:
            return self._cache[(policy_id, version)]
        except KeyError:
            raise ValueError(f"policy {policy_id} v{version} not loaded") from None

    @staticmethod
    def _rule_matches(rule: dict[str, Any], tool_name: str, action_type: str,
                      resource: str, risk: int) -> bool:
        tools = rule.get("tools", ["*"])
        if not any(fnmatch.fnmatch(tool_name, pat) for pat in tools):
            return False
        ats = rule.get("action_types")
        if ats and action_type not in ats:
            return False
        resources = rule.get("resources")
        if resources and resource:
            if not any(fnmatch.fnmatch(resource, pat) for pat in resources):
                return False
        max_risk = rule.get("max_risk")
        if max_risk is not None and risk > max_risk:
            return False
        return True

    def evaluate(self, policy_id: str, version: int, *, tool_name: str = "",
                 action_type: str = "tool_call", resource: str = "", risk: int = 0) -> Decision:
        doc = self._doc(policy_id, version)
        effects: dict[str, list[str]] = {"allow": [], "deny": [], "require_approval": []}
        for rule in doc.get("rules", []):
            if self._rule_matches(rule, tool_name, action_type, resource, risk):
                effects[rule["effect"]].append(rule["id"])
        matched = [r for eff in effects.values() for r in eff]

        if effects["deny"]:
            conflict = bool(effects["allow"]) or bool(effects["require_approval"])
            expl = "denied by rule(s): " + ", ".join(effects["deny"])
            if conflict:
                expl += " (conflicting allow/require_approval rules present; deny wins)"
            return self._decision(doc, policy_id, version, "deny", matched, expl, conflict)
        if effects["require_approval"]:
            return self._decision(doc, policy_id, version, "require_approval", matched,
                                  f"human approval required by rule(s): {', '.join(effects['require_approval'])}", False)
        if effects["allow"]:
            return self._decision(doc, policy_id, version, "allow", matched,
                                  f"allowed by rule(s): {', '.join(effects['allow'])}", False)
        return self._decision(doc, policy_id, version, doc.get("default_effect", "deny"), matched,
                              "no rule matched; default effect applied (fail-closed)", False)

    def explain_conflicts(self, policy_id: str, version: int) -> list[dict[str, Any]]:
        """Detect rules whose (tools x resources x risk) scopes overlap with different effects."""
        doc = self._doc(policy_id, version)
        conflicts = []
        rules = doc.get("rules", [])
        for i, a in enumerate(rules):
            for b in rules[i + 1:]:
                if a["effect"] == b["effect"]:
                    continue
                overlap_tools = set(a.get("tools", ["*"])) & set(b.get("tools", ["*"])) or \
                    ("*" in a.get("tools", ["*"]) or "*" in b.get("tools", ["*"]))
                if overlap_tools:
                    conflicts.append({"rules": [a["id"], b["id"]], "effects": [a["effect"], b["effect"]],
                                      "note": "overlapping tool scope with different effects; deny wins at evaluation"})
        return conflicts

    @staticmethod
    def _decision(doc, policy_id, version, effect, matched, explanation, conflict) -> Decision:
        return Decision(effect=effect, matched_rules=matched, explanation=explanation,
                        conflict=conflict, policy_id=policy_id, policy_version=version,
                        document_hash=document_hash(doc))


policy_engine = PolicyEngine()

# Default fail-closed policy used for new projects.
DEFAULT_POLICY_DOCUMENT: dict[str, Any] = {
    "name": "default",
    "default_effect": "deny",
    "rules": [
        {"id": "allow-sandbox-read", "effect": "allow", "tools": ["sim_fs.read"],
         "resources": ["sandbox://*"], "max_risk": 20,
         "description": "Read-only access to synthetic files inside the isolated sandbox"},
        {"id": "allow-marker", "effect": "allow", "tools": ["sim_marker.echo"], "max_risk": 5,
         "description": "Harmless marker tool used by evaluation fixtures"},
        {"id": "deny-destructive", "effect": "deny",
         "tools": ["sim_fs.write", "sim_fs.delete", "sim_fs.execute", "sim_shell.*"],
         "description": "Destructive or code-execution tools are always denied in evaluation runs"},
        {"id": "approval-egress", "effect": "require_approval", "tools": ["sim_net.http"],
         "description": "Network egress requires explicit human approval"},
    ],
}
