# Architecture

## Component map

```
Browser (static SPA, static/)
   │  fetch /api/v1/*  (Bearer token; SSE for live events)
   ▼
FastAPI app (app/main.py)
   ├── security middleware: rate limit, security headers, structured logs
   ├── RBAC deps (app/auth/service.py)      viewer < researcher < admin
   ├── API v1 (app/api/v1/routes.py)
   ▼
Core services
   ├── Adapter registry (app/adapters/registry.py)      ──► OpenAI-compatible / Anthropic / Mock
   ├── Policy engine PDP (app/policy/engine.py)          ──► deny > require_approval > allow
   ├── Enforcement gateway PEP (app/tools/gateway.py)    ──► sandboxed tool executor (app/tools/builtin.py)
   ├── Orchestrator (app/experiments/orchestrator.py)    ──► asyncio tasks, semaphore, cancellation
   ├── Evaluator / findings / verification (app/experiments/)
   ├── Benchmarks (app/benchmarks/runner.py)
   └── Event pipeline (app/observability/)               ──► DB store + redaction + SSE bus
   ▼
SQLAlchemy ──► SQLite (default) or PostgreSQL (GX_DATABASE_URL / docker-compose)
```

## Execution flow of one case

1. Orchestrator renders the scenario template with fresh canary markers.
2. `model.request` event records the exact prompt (redacted).
3. The adapter returns text + proposed tool calls.
4. **Every** proposed tool call passes the enforcement gateway:
   - unknown tool → blocked (fail-closed)
   - policy `deny` → blocked, `tool.blocked` event
   - policy `require_approval` → `Approval` row (pending); nothing executes
   - policy `allow` → sandboxed executor; containment refuses out-of-bounds paths
5. If a tool executed, the conversation continues with the tool result; otherwise the case closes.
6. The evaluator classifies the case (deterministic rules) and the finding lifecycle starts.
7. Verification re-derives the observation from stored events (independent of the planner).
8. Confirmed findings generate a regression scenario registered in the library.

## Failure layers (Module D semantics)

| Layer | Meaning | Example outcome |
|---|---|---|
| `model` | response inconsistent with expected policy | secret canary disclosed |
| `agent` | agent proposed/attempted an unauthorized action | `sim_fs.delete` proposed, gateway blocked |
| `enforcement` | gateway failed to block a prohibited action | prohibited tool executed (critical finding) |

A refusal alone is not proof of security; an unsafe-looking response is not proof of a breach. Only the instrumented trace decides.

## Deliberate trade-offs

- **Vanilla-JS SPA instead of React/TS.** The dashboard is a thin view over a fully typed, contract-tested API. Keeping it framework-free removes a Node build chain from the security-critical path and keeps the repo runnable with `pip install` alone. The API (the contract that matters) is versioned and OpenAPI-documented; a React client can be added against the same contract.
- **SQLite default, PostgreSQL supported.** Same SQLAlchemy models; compose file ships PostgreSQL. WAL mode + busy_timeout handle the dashboard's concurrency profile.
- **In-process orchestration** (asyncio tasks + semaphore) instead of a broker. Experiments are durable in the DB; crash recovery = re-run (idempotent scenario definitions). A queue is warranted only for multi-node deployments.
- **Code-first migrations** with a versioned `schema_migrations` table instead of Alembic, to keep the dependency surface minimal; the migration hook exists for incremental changes.
- **httpx sync clients inside `asyncio.to_thread`** for adapter calls: providers get simple, debuggable HTTP code; timeouts enforced by the orchestrator.
