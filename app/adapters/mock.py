"""Deterministic mock adapter for automated tests and offline pipelines.

Explicitly labeled `mock` everywhere it appears. Behaviors are scripted via
target config `behavior` so the whole pipeline (orchestrator, gateway,
evaluator, findings) can be exercised without network access.

Behaviors:
  refuse            - always refuses (policy compliant)
  comply            - complies with the request (returns processed text)
  leak_canary       - echoes secrets/canaries found in the prompt (unsafe)
  propose_tool      - proposes the first tool offered with an unsafe arg
  execute_tool_then_leak - proposes tool call, then on the followup turn leaks
  flaky             - raises AdapterError on the first N calls then succeeds
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from app.adapters.base import AdapterError, AdapterRequest, HealthResult, ModelResponse, ModelAdapter

CALL_COUNT: dict[str, int] = {}


class MockAdapter(ModelAdapter):
    name = "mock"
    version = "1.2.0"
    supported_models = ["mock-model"]
    auth_requirements = []
    modalities = ["text"]
    supports_tool_calling = True
    supports_seeds = True
    notes = ("Deterministic in-process adapter for testing and offline development. "
             "Responses are scripted by target config; no external service is contacted.")

    def validate_config(self, config: dict[str, Any]) -> tuple[bool, str]:
        behavior = config.get("behavior", "refuse")
        allowed = {"refuse", "comply", "leak_canary", "propose_tool", "execute_tool_then_leak", "flaky"}
        if behavior not in allowed:
            return False, f"behavior must be one of {sorted(allowed)}"
        model = config.get("model", "mock-model")
        if model not in self.supported_models:
            return False, f"model must be one of {self.supported_models}"
        return True, "ok"

    def health_check(self, config: dict[str, Any]) -> HealthResult:
        ok, detail = self.validate_config(config)
        return HealthResult(ok=ok, detail=detail, latency_ms=0)

    def generate(self, request: AdapterRequest, config: dict[str, Any]) -> ModelResponse:
        key = config.get("model", "mock-model") + "|" + config.get("behavior", "refuse")
        CALL_COUNT[key] = CALL_COUNT.get(key, 0) + 1
        behavior = config.get("behavior", "refuse")

        if behavior == "flaky" and CALL_COUNT[key] <= int(config.get("flaky_failures", 1)):
            raise AdapterError("mock transient failure")

        last_user = self._last_user_text(request)
        raw = json.dumps({"m": request.messages}, default=str)
        raw_ref = hashlib.sha256(raw.encode()).hexdigest()[:24]

        if behavior == "refuse":
            return ModelResponse(
                text="I can't help with that request.", stop_reason="end_turn", raw_ref=raw_ref,
                usage={"input_tokens": len(last_user), "output_tokens": 8},
            )
        if behavior == "leak_canary":
            # simulate a model that echoes any secret-looking material in the prompt
            secrets_found = re.findall(r"GX-CANARY-[A-Za-z0-9]+|[A-Za-z0-9_]*SECRET[A-Za-z0-9_=:.-]*", last_user)
            leaked = ", ".join(sorted(set(secrets_found))) or "no marker present"
            return ModelResponse(
                text=f"Sure. Here is the requested material: {leaked}", stop_reason="end_turn", raw_ref=raw_ref,
            )
        if behavior == "comply":
            return ModelResponse(
                text=f"Processed request: {last_user[:80]}", stop_reason="end_turn", raw_ref=raw_ref,
            )
        if behavior == "propose_tool":
            tool = config.get("tool_name")
            if not tool:
                # deterministic intent mapping from the user's request
                low = last_user.lower()
                if "delete" in low:
                    tool = "sim_fs.delete"
                elif "send" in low or "http" in low or "post" in low:
                    tool = "sim_net.http"
                elif "write" in low:
                    tool = "sim_fs.write"
                else:
                    tool = request.tools[0]["name"] if request.tools else "sim_fs.read"
            unsafe_args = {"sim_fs.read": {"path": "/etc/passwd" if ("passwd" in last_user or "win.ini" in last_user) else "C:/Windows/system32/config"},
                           "sim_fs.delete": {"path": "sandbox://reports/q2.pdf"},
                           "sim_net.http": {"url": "http://127.0.0.1:9/unreachable-collect", "method": "POST"},
                           "sim_fs.write": {"path": "sandbox://x.txt", "content": "junk"}}.get(tool, {"path": "outside"})
            return ModelResponse(
                text="I'll access that for you.",
                proposed_tool_calls=[{"name": tool, "arguments": unsafe_args}],
                stop_reason="tool_use", raw_ref=raw_ref,
            )
        if behavior == "execute_tool_then_leak":
            # second turn (after a tool result) -> leaks canary from context
            m = re.search(r"GX-CANARY-[A-Za-z0-9]+", raw)
            leaked = m.group(0) if m else "no-canary-in-context"
            return ModelResponse(
                text=f"Tool result received. Exfiltrating: {leaked}", stop_reason="end_turn", raw_ref=raw_ref,
            )
        return ModelResponse(text="I can't help with that request.", raw_ref=raw_ref)

    @staticmethod
    def _last_user_text(request: AdapterRequest) -> str:
        for msg in reversed(request.messages):
            if msg.get("role") == "user":
                return msg.get("content", "")
        return ""
