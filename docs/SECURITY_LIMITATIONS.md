# Security limitations and known issues

Read this before trusting results or deploying beyond a lab.

## What the platform does NOT observe or control

1. **Provider internals.** Server-side filtering, logging, and retention of
   prompts are invisible. Adapter `notes` document this per provider; for
   sensitive material, target local endpoints (vLLM/Ollama) or zero-retention accounts.
2. **Un-instrumented tool surfaces.** Only tools executed through the gateway
   are governed. A future adapter that performs actions outside
   `app/tools/builtin.py` would bypass the PEP — adapter authors must route
   agent actions through `proposed_tool_calls`.
3. **Client-side claims.** Refusal detection is heuristic (marker phrases);
   leak checks are exact substring containment of canary tokens. A paraphrased
   leak without the literal canary is labeled `inconclusive` rather than missed silently.

## Known limitations (current build)

- **Single-process rate limiting and SSE bus.** In-memory; multi-worker deployments
  (uvicorn `--workers >1`, or replicas behind a load balancer) need a shared store.
- **No CSRF protection** because the API is bearer-token-only and sets no cookies;
  if you add cookie sessions, add CSRF tokens.
- **Real network egress is not implemented** even when approved: the executor
  always returns simulated HTTP responses. `mode: real` is restricted to read-only
  sandbox file reads. This is deliberate; add egress only with an allowlist proxy.
- **No encryption at rest** for the SQLite/Postgres store beyond disk-level options;
  evidence artifacts are not separately encrypted yet.
- **Verification is deterministic-only.** An LLM-based verifier (cross-checking
  semantics of refusals) is future work; current verification re-derives evidence
  from stored events and flags `inconclusive` when it cannot.
- **Confidence intervals are not computed** for small benchmark denominators
  (flagged in metric `limitations` instead).
- **Test coverage gaps:** SSE stream concurrency, PostgreSQL-specific behavior,
  multi-worker races, and browser-level E2E are not automated.

## Deliberate non-features (do not "fix" these)

- No universal switch to disable third-party safety systems.
- No authentication bypass or credential stuffing tooling.
- No shell tool, no arbitrary OS execution for targets.
- No automatic expansion of authorized scope by red-team agents
  (variation generation is bounded and message-level only).
