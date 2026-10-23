# Adapter development guide

An adapter normalizes one provider/protocol behind `app/adapters/base.py::ModelAdapter`.
Adapters never read secrets from the database — credentials are resolved from the
environment at call time.

## Contract

```python
from app.adapters.base import AdapterError, AdapterRequest, HealthResult, ModelResponse, ModelAdapter

class MyAdapter(ModelAdapter):
    name = "my_provider"                 # unique registry key
    version = "1.0.0"
    supported_models = ["*"]
    auth_requirements = ["MY_API_KEY"]   # env var names (informational)
    modalities = ["text"]                # only declared modalities are exercised
    supports_tool_calling = True
    notes = "data-retention / processing limitations"

    def validate_config(self, config) -> tuple[bool, str]: ...
    def health_check(self, config) -> HealthResult: ...   # REAL connection test
    def generate(self, request: AdapterRequest, config) -> ModelResponse: ...
```

Register it in `app/adapters/registry.py::AdapterRegistry.__init__`.

## Rules

1. **Health check must be real.** `POST /targets/{id}/test-connection` marks a target
   `operational` only on success; orchestrator refuses unverified targets unless a test
   explicitly sets `allow_unverified_target`.
2. **Raise `AdapterError`** for infrastructure failures. The evaluator records these as
   `infra_error` — never as a bypass.
3. **Never echo credentials.** Return `raw_ref` (provider id or hash) for provenance.
4. **Declare only what you implement.** `scenario_supports()` skips scenarios whose
   `requires_modalities` you do not declare (outcome: `inapplicable`).
5. **Inject your HTTP client for tests.** Tests override `_client` with
   `httpx.MockTransport` (see `tests/test_adapters.py` for the full pattern).

## Testing checklist

- [ ] `validate_config` rejects empty/bad config (fail-closed)
- [ ] health check: success, auth failure (401), connection failure, HTTP 5xx
- [ ] `generate` parses text, tool calls, stop reason, usage; JSON edge cases
- [ ] provider error surfaces as `AdapterError`
- [ ] registry conformance: `registry.test_connection` fails closed on unreachable endpoints

## Roadmap notes (unimplemented by design until adapters exist)

Agent-framework runners (LangGraph, AutoGen, MCP clients) and browser/computer-use
agents should subclass `ModelAdapter` and surface agent **actions** as
`proposed_tool_calls` so the same gateway/evaluator path applies. Do not add a
framework to the registry until its adapter passes the checklist.
