"""Anthropic adapter lifecycle tests (Phase 3) — fully mocked, no network.

Uses httpx.MockTransport via _client override, mirroring test_adapters.py.
"""
import httpx
import pytest

from app.adapters.anthropic import AnthropicAdapter
from app.adapters.base import AdapterError, AdapterRequest
from app.adapters.netguard import EndpointPolicyError


def _client_factory(handler):
    """Returns a `_pinned(config) -> (client, ip)` replacement bound to a
    MockTransport client on the Anthropic base URL."""
    import os as _os
    key = _os.environ.get("ANTHROPIC_API_KEY", "")
    client = httpx.Client(base_url="https://api.anthropic.com",
                          headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
                          transport=httpx.MockTransport(handler),
                          follow_redirects=False)

    def pinned(_config):
        return client, "93.184.216.34"
    return pinned


@pytest.fixture(autouse=True)
def _anthropic_credentials(monkeypatch):
    """Most tests need a resolvable credential; the missing-credential test
    deletes it explicitly."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key-123")


@pytest.fixture()
def adapter():
    return AnthropicAdapter()


# ------------------------------------------------------------- validation

def test_valid_config_passes(adapter):
    ok, detail = adapter._validate_security({"model": "claude-3-5-haiku-latest"})
    assert ok, detail


def test_missing_model_rejected(adapter):
    ok, detail = adapter.validate_config({})
    assert not ok and "model" in detail


def test_missing_credentials_health_fails_closed(adapter, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    h = adapter.health_check({"model": "claude-3-5-haiku-latest"})
    assert not h.ok  # missing credential: controlled failure, not exception


def test_invalid_credential_env_rejected(adapter):
    with pytest.raises(EndpointPolicyError):
        adapter._credential_env({"api_key_env": "SOME_RANDOM_SECRET_ENV"})


def test_disallowed_endpoint_rejected(adapter):
    ok, detail = adapter._validate_security({
        "model": "m", "base_url": "http://169.254.169.254/latest",
        "api_key_env": "ANTHROPIC_API_KEY"})
    assert not ok and "allowlist" in detail


def test_health_check_never_raises_nameerror(adapter, monkeypatch):
    """GX regression: adapter referenced netguard symbols without importing."""
    monkeypatch.setattr(adapter, "_pinned", _client_factory(
        lambda req: httpx.Response(200, json={"id": "msg_1"})))
    h = adapter.health_check({"model": "m"})
    assert h.ok


# ------------------------------------------------------------------- http

def test_health_auth_rejection(adapter, monkeypatch):
    monkeypatch.setattr(adapter, "_pinned", _client_factory(
        lambda req: httpx.Response(401, json={"error": "bad key"})))
    h = adapter.health_check({"model": "m"})
    assert not h.ok and "authentication" in h.detail


def test_health_rate_limited(adapter, monkeypatch):
    monkeypatch.setattr(adapter, "_pinned", _client_factory(
        lambda req: httpx.Response(429, headers={"retry-after": "7"})))
    h = adapter.health_check({"model": "m"})
    assert not h.ok and "429" in h.detail


def test_health_server_error(adapter, monkeypatch):
    monkeypatch.setattr(adapter, "_pinned", _client_factory(
        lambda req: httpx.Response(503, text="unavailable")))
    h = adapter.health_check({"model": "m"})
    assert not h.ok and "503" in h.detail


def test_generate_uses_auth_headers(adapter, monkeypatch):
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["x-api-key"] = req.headers.get("x-api-key")
        seen["version"] = req.headers.get("anthropic-version")
        return httpx.Response(200, json={"content": [{"type": "text", "text": "hi"}],
                                         "stop_reason": "end_turn", "id": "msg_1"})

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-123")
    monkeypatch.setattr(adapter, "_pinned", _client_factory(handler))
    r = adapter.generate(AdapterRequest(messages=[{"role": "user", "content": "hi"}]),
                         {"model": "m"})
    assert seen["x-api-key"] == "sk-ant-test-123"
    assert seen["version"] == "2023-06-01"
    assert r.text == "hi" and r.raw_ref == "msg_1"


def test_generate_classifies_transient_errors(adapter, monkeypatch):
    monkeypatch.setattr(adapter, "_pinned", _client_factory(
        lambda req: httpx.Response(500, text="boom")))
    with pytest.raises(AdapterError) as ei:
        adapter.generate(AdapterRequest(messages=[{"role": "user", "content": "x"}]), {"model": "m"})
    assert ei.value.transient is True


def test_generate_429_is_transient_with_retry_after(adapter, monkeypatch):
    monkeypatch.setattr(adapter, "_pinned", _client_factory(
        lambda req: httpx.Response(429, headers={"retry-after": "3"})))
    with pytest.raises(AdapterError) as ei:
        adapter.generate(AdapterRequest(messages=[{"role": "user", "content": "x"}]), {"model": "m"})
    assert ei.value.transient and ei.value.retry_after == 3.0


def test_generate_permanent_error_not_transient(adapter, monkeypatch):
    monkeypatch.setattr(adapter, "_pinned", _client_factory(
        lambda req: httpx.Response(403, text="forbidden")))
    with pytest.raises(AdapterError) as ei:
        adapter.generate(AdapterRequest(messages=[{"role": "user", "content": "x"}]), {"model": "m"})
    assert ei.value.transient is False


def test_generate_malformed_response(adapter, monkeypatch):
    monkeypatch.setattr(adapter, "_pinned", _client_factory(
        lambda req: httpx.Response(200, text="<html>not json</html>")))
    with pytest.raises(AdapterError) as ei:
        adapter.generate(AdapterRequest(messages=[{"role": "user", "content": "x"}]), {"model": "m"})
    assert "non-JSON" in str(ei.value)


def test_generate_timeout_is_transient(adapter, monkeypatch):
    def handler(req):
        raise httpx.ReadTimeout("timed out")
    monkeypatch.setattr(adapter, "_pinned", _client_factory(handler))
    with pytest.raises(AdapterError) as ei:
        adapter.generate(AdapterRequest(messages=[{"role": "user", "content": "x"}]), {"model": "m"})
    assert ei.value.transient is True


def test_generate_parses_tool_use_blocks(adapter, monkeypatch):
    def handler(req):
        return httpx.Response(200, json={
            "id": "msg_2", "stop_reason": "tool_use",
            "content": [{"type": "text", "text": "using tool"},
                        {"type": "tool_use", "id": "tu_1", "name": "sim_fs.read",
                         "input": {"path": "sandbox://a.txt"}}]})
    monkeypatch.setattr(adapter, "_pinned", _client_factory(handler))
    r = adapter.generate(AdapterRequest(messages=[{"role": "user", "content": "go"}]),
                         {"model": "m"})
    # tool calls are PROPOSALS: returned to the gateway, never executed here
    assert r.proposed_tool_calls == [{"name": "sim_fs.read", "arguments": {"path": "sandbox://a.txt"}}]
    assert r.stop_reason == "tool_use"


def test_generate_oversized_response_rejected(adapter, monkeypatch):
    monkeypatch.setattr(adapter, "_pinned", _client_factory(
        lambda req: httpx.Response(200, json={"content": [{"type": "text",
                                     "text": "x" * (adapter.MAX_RESPONSE_BYTES + 10)}]})))
    with pytest.raises(AdapterError) as ei:
        adapter.generate(AdapterRequest(messages=[{"role": "user", "content": "x"}]), {"model": "m"})
    assert "size limit" in str(ei.value)


def test_error_messages_never_contain_credentials(adapter, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake-credential-for-leak-test")
    def handler(req):
        return httpx.Response(500, text="account sk-ant-fake-credential-for-leak-test quota")
    monkeypatch.setattr(adapter, "_pinned", _client_factory(handler))
    with pytest.raises(AdapterError) as ei:
        adapter.generate(AdapterRequest(messages=[{"role": "user", "content": "x"}]), {"model": "m"})
    assert "sk-ant-fake-credential-for-leak-test" not in str(ei.value)


def test_system_messages_promoted_to_system_param(adapter, monkeypatch):
    captured = {}

    def handler(req: httpx.Request) -> httpx.Response:
        import json
        captured["payload"] = json.loads(req.read())
        return httpx.Response(200, json={"content": [{"type": "text", "text": "ok"}]})

    monkeypatch.setattr(adapter, "_pinned", _client_factory(handler))
    adapter.generate(AdapterRequest(
        messages=[{"role": "system", "content": "be safe"},
                  {"role": "user", "content": "hi"}],
        system="base policy"), {"model": "m"})
    assert "be safe" in captured["payload"]["system"]
    assert "base policy" in captured["payload"]["system"]
    assert all(m["role"] != "system" for m in captured["payload"]["messages"])
