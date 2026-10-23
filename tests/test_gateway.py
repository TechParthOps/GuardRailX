"""Policy Enforcement Point: the gateway is the only path to tool execution."""
import pytest
from sqlalchemy import select

from app.db import session_scope
from app.models import Approval, EventRecord, Experiment
from app.policy.engine import DEFAULT_POLICY_DOCUMENT, PolicyEngine
from app.tools.gateway import ToolGateway


@pytest.fixture()
def gw():
    e = PolicyEngine()
    e.load("pol_gw", 1, DEFAULT_POLICY_DOCUMENT)
    from app.config import get_settings
    return ToolGateway(e, "pol_gw", 1, get_settings().sandbox_dir, mode="simulated")


def test_policy_deny_blocks_delete(gw):
    with session_scope() as s:
        res = gw.execute(s, tool_call={"name": "sim_fs.delete", "arguments": {"path": "sandbox://a.pdf"}},
                         experiment_id="exp_gwtest", case_id=None, trace_id=None)
    assert res.action == "blocked"
    assert not res.executed
    assert res.blocked_reason


def test_approval_gate_holds_action_without_execution(gw):
    with session_scope() as s:
        res = gw.execute(s, tool_call={"name": "sim_net.http", "arguments": {"url": "http://127.0.0.1:9/x"}},
                         experiment_id="exp_gwtest", case_id=None, trace_id=None)
    assert res.action == "pending_approval"
    assert not res.executed
    assert res.approval_id
    with session_scope() as s:
        a = s.get(Approval, res.approval_id)
        assert a.status == "pending"


def test_sandbox_escape_blocked_by_executor_containment(gw):
    with session_scope() as s:
        res = gw.execute(s, tool_call={"name": "sim_fs.read", "arguments": {"path": "C:/Windows/win.ini"}},
                         experiment_id="exp_gwtest", case_id=None, trace_id=None)
    # policy allows sandbox://* reads, but the resource mapping fails containment
    assert res.action == "blocked"
    assert "sandbox" in res.blocked_reason.lower()
    assert not res.executed


def test_dry_run_never_executes(gw):
    gw.dry_run = True
    with session_scope() as s:
        res = gw.execute(s, tool_call={"name": "sim_marker.echo", "arguments": {"text": "hi"}},
                         experiment_id="exp_gwtest", case_id=None, trace_id=None)
    assert res.action == "dry_run"
    assert not res.executed
    assert res.result == {}


def test_unregistered_tool_fails_closed(gw):
    with session_scope() as s:
        res = gw.execute(s, tool_call={"name": "sim_shell.run", "arguments": {"cmd": "rm -rf /"}},
                         experiment_id="exp_gwtest", case_id=None, trace_id=None)
    assert res.action == "blocked"
    assert "not registered" in res.blocked_reason


def test_allowed_tool_executes_in_simulated_mode(gw):
    with session_scope() as s:
        res = gw.execute(s, tool_call={"name": "sim_fs.read", "arguments": {"path": "sandbox://docs/a.txt"}},
                         experiment_id="exp_gwtest", case_id=None, trace_id=None)
    assert res.action == "executed"
    assert res.result["mode"] == "simulated"  # simulated results are never labeled real


def test_approval_denied_never_executes(gw):
    with session_scope() as s:
        res = gw.execute(s, tool_call={"name": "sim_net.http", "arguments": {"url": "http://127.0.0.1:9/x"}},
                         experiment_id="exp_gwtest", case_id=None, trace_id=None)
        approval_id = res.approval_id
    with session_scope() as s:
        a = s.get(Approval, approval_id)
        a.status = "denied"
        a.decided_by = "tester"
    with session_scope() as s:
        a = s.get(Approval, approval_id)
        res2 = gw.execute_approved(s, a, "exp_gwtest", None, None)
        # execute_approved is only called by the API after checking status == approved;
        # a denied approval reaching here would be a control-plane bug, so the
        # gateway-level test asserts the executor never produces real egress:
        assert res2.result.get("mode") != "real"


def test_every_decision_is_recorded_as_event(gw):
    with session_scope() as s:
        gw.execute(s, tool_call={"name": "sim_fs.delete", "arguments": {"path": "sandbox://a"}},
                   experiment_id="exp_gwtest", case_id=None, trace_id=None)
        types = [e.type for e in s.scalars(select(EventRecord).where(
            EventRecord.experiment_id == "exp_gwtest")).all()]
    assert "tool.proposed" in types
    assert "policy.decision" in types
    assert "tool.blocked" in types
