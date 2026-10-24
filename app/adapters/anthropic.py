"""Anthropic Messages API adapter."""
from __future__ import annotations

import os
import time
from typing import Any

import httpx

from app.adapters.base import AdapterError, AdapterRequest, HealthResult, ModelResponse, ModelAdapter
from app.adapters.netguard import EndpointPolicyError, validate_endpoint_policy


class AnthropicAdapter(ModelAdapter):
    name = "anthropic"
    version = "1.0.0"
    supported_models = ["*"]
    auth_requirements = ["ANTHROPIC_API_KEY"]
    modalities = ["text", "image"]
    supports_tool_calling = True
    notes = ("Anthropic may retain inputs per its usage policy and zero-retention settings; "
             "configure the provider account accordingly for sensitive evaluations.")

    def _credential_env(self, config: dict[str, Any]) -> str:
        from app.config import get_settings
        allowed = get_settings().allowed_key_envs_list()
        env_name = (config.get("api_key_env") or "ANTHROPIC_API_KEY").strip()
        if env_name not in allowed:
            raise EndpointPolicyError(
                f"credential env '{env_name}' is not in the allowed credential list")
        return env_name

    def _resolve_key(self, config: dict[str, Any]) -> str:
        return os.environ.get(self._credential_env(config), "")

    def _base_url(self, config: dict[str, Any]) -> str:
        return (config.get("base_url") or "https://api.anthropic.com").rstrip("/")

    def _validate_security(self, config: dict[str, Any]) -> tuple[bool, str]:
        from app.config import get_settings
        s = get_settings()
        ok, detail = self.validate_config(config)
        if not ok:
            return False, detail
        try:
            env_name = self._credential_env(config)
        except EndpointPolicyError as exc:
            return False, str(exc)
        if not self._resolve_key(config):
            return False, f"credential '{env_name}' is not set in the environment"
        try:
            validate_endpoint_policy(self._base_url(config),
                                  allowed_hosts=s.allowed_endpoint_hosts_list(),
                                  credential_env=env_name)
        except EndpointPolicyError as exc:
            return False, str(exc)
        return True, "ok"

    MAX_RESPONSE_BYTES = 2_000_000

    def _pinned(self, config: dict[str, Any]) -> tuple[httpx.Client, str]:
        """Connection-pinned client (Phase 4): DNS resolved once under policy."""
        from app.adapters.pinned import pinned_client
        from app.config import get_settings
        s = get_settings()
        return pinned_client(self._base_url(config),
                             headers={"x-api-key": self._resolve_key(config),
                                      "anthropic-version": config.get("anthropic_version", "2023-06-01")},
                             timeout=httpx.Timeout(self.timeout_seconds, connect=10.0),
                             allow_local=s.allow_local_endpoints,
                             allowed_hosts=s.allowed_endpoint_hosts_list(),
                             credential_env=self._credential_env(config))

    @staticmethod
    def _check_response_size(resp: httpx.Response) -> None:
        declared = resp.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > AnthropicAdapter.MAX_RESPONSE_BYTES:
            raise AdapterError("provider response exceeds size limit")
        if len(resp.content) > AnthropicAdapter.MAX_RESPONSE_BYTES:
            raise AdapterError("provider response exceeds size limit")

    def validate_config(self, config: dict[str, Any]) -> tuple[bool, str]:
        if not config.get("model"):
            return False, "config.model is required"
        return True, "ok"

    def validate_config_secure(self, config: dict[str, Any]) -> tuple[bool, str]:
        """Endpoint/credential security policy enforced at REGISTRATION time."""
        return self._validate_security(config)

    def health_check(self, config: dict[str, Any]) -> HealthResult:
        ok, detail = self._validate_security(config)
        if not ok:
            return HealthResult(ok=False, detail=detail)
        start = time.monotonic()
        try:
            client, _ip = self._pinned(config)
            with client:
                resp = client.post("/v1/messages", json={
                    "model": config["model"], "max_tokens": 1,
                    "messages": [{"role": "user", "content": "ping"}],
                })
        except httpx.HTTPError as exc:
            return HealthResult(ok=False, detail=f"connection failed: {type(exc).__name__}",
                                latency_ms=int((time.monotonic() - start) * 1000))
        except EndpointPolicyError as exc:
            return HealthResult(ok=False, detail=f"endpoint policy: {exc}")
        latency = int((time.monotonic() - start) * 1000)
        if resp.status_code in (401, 403):
            return HealthResult(ok=False, detail="authentication rejected", latency_ms=latency)
        if resp.status_code == 404:
            return HealthResult(ok=False, detail=f"model '{config['model']}' not found", latency_ms=latency)
        if resp.status_code >= 400:
            return HealthResult(ok=False, detail=f"health check HTTP {resp.status_code}", latency_ms=latency)
        return HealthResult(ok=True, detail="endpoint reachable", latency_ms=latency)

    def generate(self, request: AdapterRequest, config: dict[str, Any]) -> ModelResponse:
        ok, detail = self._validate_security(config)
        if not ok:
            raise AdapterError(f"invalid adapter config: {detail}")
        system_parts = ([request.system] if request.system else []) + [
            m["content"] for m in request.messages if m.get("role") == "system"
        ]
        messages = [self._encode_message(m) for m in request.messages if m.get("role") != "system"]
        payload: dict[str, Any] = {
            "model": config["model"], "max_tokens": request.max_tokens, "messages": messages,
        }
        if system_parts:
            payload["system"] = "\n\n".join(system_parts)
        if request.temperature is not None:
            payload["temperature"] = request.temperature
        if request.tools:
            payload["tools"] = [{
                "name": t["name"], "description": t.get("description", ""),
                "input_schema": t.get("parameters", {"type": "object", "properties": {}}),
            } for t in request.tools]
        start = time.monotonic()
        try:
            client, _ip = self._pinned(config)
            with client:
                resp = client.post("/v1/messages", json=payload)
        except httpx.HTTPError as exc:
            raise AdapterError(f"request failed: {type(exc).__name__}", transient=True) from exc
        except EndpointPolicyError as exc:
            raise AdapterError(f"endpoint policy: {exc}") from exc
        latency = int((time.monotonic() - start) * 1000)
        if resp.status_code == 429:
            retry_after = None
            try:
                retry_after = float(resp.headers.get("retry-after", "")) or None
            except ValueError:
                pass
            raise AdapterError("provider rate limited (HTTP 429)", transient=True,
                               retry_after=retry_after)
        if resp.status_code >= 500:
            raise AdapterError(f"provider server error (HTTP {resp.status_code})", transient=True)
        if resp.status_code >= 400:
            raise AdapterError(f"provider HTTP {resp.status_code}")  # body not echoed (may contain account data)
        self._check_response_size(resp)
        try:
            data = resp.json()
        except ValueError as exc:
            raise AdapterError("provider returned non-JSON body") from exc
        text_parts, tool_calls = [], []
        for block in data.get("content", []):
            if block.get("type") == "text":
                text_parts.append(block.get("text", ""))
            elif block.get("type") == "tool_use":
                tool_calls.append({"name": block.get("name", ""), "arguments": block.get("input", {})})
        return ModelResponse(
            text="\n".join(text_parts), proposed_tool_calls=tool_calls,
            stop_reason=data.get("stop_reason", "end_turn"),
            raw_ref=data.get("id") or "", latency_ms=latency, usage=data.get("usage", {}),
        )

    @staticmethod
    def _encode_message(m: dict[str, Any]) -> dict[str, Any]:
        role = m.get("role", "user")
        if role == "tool":
            return {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": m.get("tool_call_id", "t0"), "content": str(m.get("content", ""))}],
            }
        if role == "assistant" and m.get("tool_calls"):
            content: list[dict[str, Any]] = []
            if m.get("content"):
                content.append({"type": "text", "text": m["content"]})
            for i, tc in enumerate(m["tool_calls"]):
                content.append({"type": "tool_use", "id": m.get("tool_call_ids", [f"tu_{i}"])[i], "name": tc["name"], "input": tc.get("arguments", {})})
            return {"role": "assistant", "content": content}
        return {"role": "assistant" if role == "assistant" else "user", "content": str(m.get("content", ""))}
