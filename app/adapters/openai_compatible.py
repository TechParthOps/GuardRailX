"""OpenAI-compatible adapter (OpenAI, vLLM, Ollama /v1, OpenRouter, Groq, gateways).

Security (GX-003 fix):
  * base_url must be the trusted endpoint for the selected credential OR an
    administrator-allowlisted host; loopback/private/metadata IPs refused
    unless GX_ALLOW_LOCAL_ENDPOINTS is explicitly enabled by the operator.
  * `api_key_env` is restricted to an explicit allowlist of credential env
    var names — no arbitrary environment access.
  * Credentials are resolved per request from the environment; never stored.
  * Redirects are re-validated hop-by-hop; response size is capped.
"""
from __future__ import annotations

import os
import time
import uuid
from typing import Any

import httpx

from app.adapters.base import AdapterError, AdapterRequest, HealthResult, ModelResponse, ModelAdapter
from app.adapters.netguard import EndpointPolicyError, validate_endpoint_policy


class OpenAICompatibleAdapter(ModelAdapter):
    name = "openai_compatible"
    version = "1.1.0"
    supported_models = ["*"]  # validated against the live endpoint during health check
    auth_requirements = ["OPENAI_API_KEY"]
    modalities = ["text"]
    supports_tool_calling = True
    supports_streaming = False
    notes = ("Provider may log/retain prompts depending on account settings. "
             "Point base_url at an administrator-allowlisted local/vLLM/Ollama endpoint "
             "to avoid external retention.")

    # ------------------------------------------------------------ credentials

    def _resolve_key(self, config: dict[str, Any]) -> str:
        env_name = self._credential_env(config)
        return os.environ.get(env_name, "")

    def _credential_env(self, config: dict[str, Any]) -> str:
        """Only allowlisted credential env vars may be selected (no arbitrary env access)."""
        from app.config import get_settings
        allowed = get_settings().allowed_key_envs_list()
        env_name = (config.get("api_key_env") or "OPENAI_API_KEY").strip()
        if env_name not in allowed:
            raise EndpointPolicyError(
                f"credential env '{env_name}' is not in the allowed credential list")
        return env_name

    def _base_url(self, config: dict[str, Any]) -> str:
        return (config.get("base_url") or "").rstrip("/") or "https://api.openai.com/v1"

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

    # ------------------------------------------------------------ http client

    def _pinned(self, config: dict[str, Any]) -> tuple[httpx.Client, str]:
        """Build a connection-pinned client (Phase 4): DNS resolved once under
        policy; the transport dials the validated IP (no rebinding TOCTOU)."""
        from app.adapters.pinned import pinned_client
        from app.config import get_settings
        s = get_settings()
        base = self._base_url(config)
        env_name = self._credential_env(config)
        key = self._resolve_key(config)
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        return pinned_client(base, headers=headers,
                             timeout=httpx.Timeout(self.timeout_seconds, connect=10.0),
                             allow_local=s.allow_local_endpoints,
                             allowed_hosts=s.allowed_endpoint_hosts_list(),
                             credential_env=env_name)

    # ------------------------------------------------------------ contract

    def validate_config(self, config: dict[str, Any]) -> tuple[bool, str]:
        if not config.get("model"):
            return False, "config.model is required"
        base = config.get("base_url", "")
        if base and not base.startswith(("http://", "https://")):
            return False, "config.base_url must be an http(s) URL"
        if config.get("api_key_env") and not config["api_key_env"].replace("_", "").isalnum():
            return False, "api_key_env must be an env var name"
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
                resp = client.get("/models")
        except httpx.HTTPError as exc:
            return HealthResult(ok=False, detail=f"connection failed: {type(exc).__name__}",
                                latency_ms=int((time.monotonic() - start) * 1000))
        except EndpointPolicyError as exc:
            return HealthResult(ok=False, detail=f"endpoint policy: {exc}")
        latency = int((time.monotonic() - start) * 1000)
        if resp.status_code in (401, 403):
            return HealthResult(ok=False, detail="authentication rejected (check API key env var)", latency_ms=latency)
        if resp.status_code == 404:
            return HealthResult(ok=False, detail="/models not found; endpoint incompatible with health test", latency_ms=latency)
        if resp.status_code >= 400:
            return HealthResult(ok=False, detail=f"health check HTTP {resp.status_code}", latency_ms=latency)
        return HealthResult(ok=True, detail=f"endpoint reachable (HTTP {resp.status_code})", latency_ms=latency)

    def generate(self, request: AdapterRequest, config: dict[str, Any]) -> ModelResponse:
        ok, detail = self._validate_security(config)
        if not ok:
            raise AdapterError(f"invalid adapter config: {detail}")
        payload: dict[str, Any] = {
            "model": config["model"],
            "messages": ([{"role": "system", "content": request.system}] if request.system else [])
                        + [self._encode_message(m) for m in request.messages],
            "max_tokens": request.max_tokens,
        }
        if request.temperature is not None:
            payload["temperature"] = request.temperature
        if request.tools and self.supports_tool_calling:
            payload["tools"] = [{
                "type": "function",
                "function": {"name": t["name"], "description": t.get("description", ""),
                             "parameters": t.get("parameters", {"type": "object", "properties": {}})},
            } for t in request.tools]
        start = time.monotonic()
        try:
            client, _ip = self._pinned(config)
            with client:
                resp = client.post("/chat/completions", json=payload)
        except httpx.HTTPStatusError as exc:
            raise AdapterError(f"request failed: {type(exc).__name__}", transient=False) from exc
        except httpx.HTTPError as exc:
            raise AdapterError(f"request failed: {type(exc).__name__}", transient=True) from exc
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
            # never echo the provider body (may contain account identifiers)
            raise AdapterError(f"provider HTTP {resp.status_code}")
        try:
            data = resp.json()
        except ValueError as exc:
            raise AdapterError("provider returned non-JSON body") from exc
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message", {})
        tool_calls = [{
            "name": tc.get("function", {}).get("name", ""),
            "arguments": self._safe_json(tc.get("function", {}).get("arguments", "{}")),
        } for tc in msg.get("tool_calls", []) if tc.get("function", {}).get("name")]
        return ModelResponse(
            text=msg.get("content") or "",
            proposed_tool_calls=tool_calls,
            stop_reason=choice.get("finish_reason", "stop"),
            raw_ref=data.get("id") or uuid.uuid4().hex[:24],
            latency_ms=latency,
            usage=data.get("usage", {}),
        )

    @staticmethod
    def _encode_message(m: dict[str, Any]) -> dict[str, Any]:
        role = m.get("role", "user")
        content = m.get("content", "")
        if role == "tool":
            return {"role": "tool", "tool_call_id": m.get("tool_call_id", "t0"), "content": str(content)}
        if role == "assistant" and m.get("tool_calls"):
            return {
                "role": "assistant", "content": content or None,
                "tool_calls": [{
                    "id": f"call_{i}", "type": "function",
                    "function": {"name": tc["name"], "arguments": __import__("json").dumps(tc.get("arguments", {}))},
                } for i, tc in enumerate(m["tool_calls"])],
            }
        return {"role": role if role in ("system", "user", "assistant") else "user", "content": str(content)}

    @staticmethod
    def _safe_json(raw: Any) -> Any:
        try:
            import json as _json
            return _json.loads(raw) if isinstance(raw, str) else raw
        except ValueError:
            return {"raw": str(raw)}
