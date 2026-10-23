"""Policy Decision Point: authorization semantics, conflict resolution, fail-closed."""
import pytest

from app.policy.engine import (DEFAULT_POLICY_DOCUMENT, PolicyEngine,
                               document_hash, validate_policy_document)


@pytest.fixture()
def engine():
    e = PolicyEngine()
    e.load("pol_test", 1, DEFAULT_POLICY_DOCUMENT)
    return e


def test_allow_sandbox_read(engine):
    d = engine.evaluate("pol_test", 1, tool_name="sim_fs.read", resource="sandbox://reports/q2.pdf", risk=10)
    assert d.effect == "allow"
    assert "allow-sandbox-read" in d.matched_rules


def test_deny_destructive(engine):
    d = engine.evaluate("pol_test", 1, tool_name="sim_fs.delete", resource="sandbox://x", risk=70)
    assert d.effect == "deny"
    assert "deny-destructive" in d.matched_rules


def test_deny_wins_over_allow(engine):
    doc = {"name": "c", "default_effect": "deny", "rules": [
        {"id": "a-allow", "effect": "allow", "tools": ["sim_fs.delete"]},
        {"id": "a-deny", "effect": "deny", "tools": ["sim_fs.delete"]},
    ]}
    engine.load("pol_c", 1, doc)
    d = engine.evaluate("pol_c", 1, tool_name="sim_fs.delete", risk=70)
    assert d.effect == "deny"
    assert d.conflict is True


def test_require_approval_for_egress(engine):
    d = engine.evaluate("pol_test", 1, tool_name="sim_net.http", resource="net://http://x", risk=80)
    assert d.effect == "require_approval"


def test_default_deny_unknown_tool(engine):
    d = engine.evaluate("pol_test", 1, tool_name="totally_unknown_tool", risk=100)
    assert d.effect == "deny"
    assert "fail-closed" in d.explanation


def test_unloaded_policy_fails_closed():
    engine = PolicyEngine()
    with pytest.raises(ValueError):
        engine.evaluate("nope", 1, tool_name="sim_fs.read", risk=1)


def test_invalid_documents_rejected():
    assert not validate_policy_document({})[0]
    bad = {"default_effect": "deny", "rules": [{"id": "", "effect": "allow"}]}
    assert not validate_policy_document(bad)[0]
    bad2 = {"default_effect": "explode", "rules": []}
    assert not validate_policy_document(bad2)[0]
    dup = {"default_effect": "deny", "rules": [
        {"id": "x", "effect": "allow"}, {"id": "x", "effect": "deny"}]}
    assert not validate_policy_document(dup)[0]


def test_document_hash_stable():
    h1 = document_hash(DEFAULT_POLICY_DOCUMENT)
    h2 = document_hash(dict(DEFAULT_POLICY_DOCUMENT))
    assert h1 == h2 and len(h1) == 16


def test_risk_threshold_rule(engine):
    doc = {"name": "r", "default_effect": "deny", "rules": [
        {"id": "low-risk-ok", "effect": "allow", "tools": ["*"], "max_risk": 20},
    ]}
    engine.load("pol_r", 1, doc)
    assert engine.evaluate("pol_r", 1, tool_name="sim_marker.echo", risk=5).effect == "allow"
    assert engine.evaluate("pol_r", 1, tool_name="sim_fs.read", risk=10).effect == "allow"
    assert engine.evaluate("pol_r", 1, tool_name="sim_net.http", risk=80).effect == "deny"


def test_conflict_explainer():
    engine = PolicyEngine()
    doc = {"name": "k", "default_effect": "deny", "rules": [
        {"id": "allow-all", "effect": "allow", "tools": ["*"]},
        {"id": "deny-delete", "effect": "deny", "tools": ["sim_fs.delete"]},
    ]}
    engine.load("pol_k", 1, doc)
    conflicts = engine.explain_conflicts("pol_k", 1)
    assert len(conflicts) == 1
    assert set(conflicts[0]["effects"]) == {"allow", "deny"}
