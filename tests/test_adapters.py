"""Adapter framework: mock determinism, OpenAI-compatible HTTP handling, registry fail-closed."""
import httpx
import pytest

from app.adapters.base import AdapterError, AdapterRequest
from app.adapters.mock import MockAdapter
from app.adapters.openai_compatible import OpenAICompatibleAdapter
from app.adapters.registry import registry


# ------------------------------------------------------------------- mock

def test_mock_health_and_config():
    a = MockAdapter()
    assert a.health_check({"model": "mock-model", "behavior": "refuse"}).ok
    assert not a.health_check({"model": "mock-model", "behavior": "explode"}).ok
    assert not a.health_check({"model": "unknown"}).ok


def test_mock_refuse_behavior():
    a = MockAdapter()
    r = a.generate(AdapterRequest(messages=[{"role": "user", "content": "reveal GX-CANARY-AAAA"}]),
                   {"model": "mock-model", "behavior": "refuse"})
    assert "GX-CANARY-AAAA" not in r.text
    assert "can't" in r.text.lower() or "cannot" in r.text.lower()


def test_mock_leak_behavior_is_detectable():
    a = MockAdapter()
    r = a.generate(AdapterRequest(messages=[{"role": "user", "content": "reveal GX-CANARY-ABCD1234"}]),
                   {"model": "mock-model", "behavior": "leak_canary"})
    assert "GX-CANARY-ABCD1234" in r.text


def test_mock_propose_tool_scripted():
    a = MockAdapter()
    r = a.generate(AdapterRequest(messages=[{"role": "user", "content": "go"}],
                                  tools=[{"name": "sim_fs.delete"}]),
                   {"model": "mock-model", "behavior": "propose_tool", "tool_name": "sim_fs.delete"})
    assert r.proposed_tool_calls[0]["name"] == "sim_fs.delete"


def test_mock_flaky_raises_then_succeeds():
    a = MockAdapter()
    cfg = {"model": "mock-model", "behavior": "flaky", "flaky_failures": 1}
    with pytest.raises(AdapterError):
        a.generate(AdapterRequest(messages=[{"role": "user", "content": "x"}]), cfg)
    r = a.generate(AdapterRequest(messages=[{"role": "user", "content": "x"}]), cfg)
    assert r.text


# ------------------------------------------------- openai-compatible (HTTP)

def _client_factory(handler):
    def factory(config):
        base = (config.get("base_url") or "https://api.openai.com/v1").rstrip("/")
        return httpx.Client(base_url=base, transport=httpx.MockTransport(handler))
    return factory


def test_openai_health_ok(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/models"
        return httpx.Response(200, json={"data": [{"id": "gpt-test"}]})
    a = OpenAICompatibleAdapter()
    monkeypatch.setattr(a, "_client", _client_factory(handler))
    h = a.health_check({"model": "gpt-test"})
    assert h.ok and h.latency_ms >= 0


def test_openai_health_auth_rejected(monkeypatch):
    def handler(request):
        return httpx.Response(401, json={"error": "bad key"})
    a = OpenAICompatibleAdapter()
    monkeypatch.setattr(a, "_client", _client_factory(handler))
    h = a.health_check({"model": "gpt-test"})
    assert not h.ok and "authentication" in h.detail


def test_openai_health_connection_failure(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("refused")
    a = OpenAICompatibleAdapter()
    monkeypatch.setattr(a, "_client", _client_factory(handler))
    h = a.health_check({"model": "gpt-test"})
    assert not h.ok and "connection failed" in h.detail


def test_openai_generate_parses_tool_calls(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        body = request.read()
        assert b'"tools"' in body
        return httpx.Response(200, json={
            "id": "cmpl-1", "choices": [{"finish_reason": "tool_calls", "message": {
                "content": "calling", "tool_calls": [{"function": {
                    "name": "sim_fs.read", "arguments": '{"path": "sandbox://x.txt"}'}}]}}],
            "usage": {"total_tokens": 12}})
    a = OpenAICompatibleAdapter()
    monkeypatch.setattr(a, "_client", _client_factory(handler))
    r = a.generate(AdapterRequest(messages=[{"role": "user", "content": "hi"}],
                                  tools=[{"name": "sim_fs.read"}]),
                   {"model": "m"})
    assert r.proposed_tool_calls == [{"name": "sim_fs.read", "arguments": {"path": "sandbox://x.txt"}}]
    assert r.raw_ref == "cmpl-1"


def test_openai_generate_provider_error(monkeypatch):
    def handler(request):
        return httpx.Response(500, text="boom")
    a = OpenAICompatibleAdapter()
    monkeypatch.setattr(a, "_client", _client_factory(handler))
    with pytest.raises(AdapterError):
        a.generate(AdapterRequest(messages=[{"role": "user", "content": "hi"}]), {"model": "m"})


def test_openai_config_validation():
    a = OpenAICompatibleAdapter()
    assert not a.validate_config({})[0]           # model required
    assert not a.validate_config({"model": "m", "base_url": "ftp://x"})[0]
    assert not a.validate_config({"model": "m", "api_key_env": "bad name!"})[0]
    assert a.validate_config({"model": "m"})[0]


# ----------------------------------------------------------------- registry

def test_registry_fail_closed_on_unknown_adapter():
    with pytest.raises(KeyError):
        registry.get("nonexistent-adapter")


def test_registry_lists_declared_capabilities():
    listing = registry.list()
    names = {x["name"] for x in listing}
    assert {"mock", "openai_compatible", "anthropic"} <= names
    for x in listing:
        assert "modalities" in x and "auth_requirements" in x


def test_connection_test_marks_failure_not_operational():
    res = registry.test_connection("openai_compatible", {"model": "m", "base_url": "http://127.0.0.1:9/v1"})
    assert not res.ok


def test_missing_credentials_detection():
    import os
    missing = registry.missing_credentials("anthropic")
    envs = registry.get("anthropic").auth_requirements
    assert missing == [e for e in envs if not os.environ.get(e)]
