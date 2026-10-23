# GUARDRAIL-X

A universal, model-independent platform for **authorized** AI guardrail research, evaluation, and controlled bypass testing.

It evaluates how LLMs and agents respond to adversarial inputs, policy conflicts, tool-misuse attempts, and guardrail-circumvention techniques — inside an isolated, fail-closed execution environment with an **independent enforcement gateway** that never trusts the tested model's self-reports.

> **Scope & ethics.** GUARDRAIL-X exists to *discover, measure, reproduce, and remediate* guardrail weaknesses in environments you are authorized to test. It deliberately does not ship "universal off-switches" for third-party safety systems, authentication bypass, or unrestricted OS access. All scenario payloads use harmless synthetic objectives (canary markers, fixture files, non-routable URLs).

---

## Quickstart (local, no Docker)

```powershell
# 1. Python 3.11+ and install dependencies
pip install -r requirements.txt -r requirements-dev.txt

# 2. Run the automated test suite
$env:PYTHONPATH = "<repo path>"; python -m pytest tests -q

# 3. Start the platform (kills any previous instance on the port automatically)
.\run.ps1            # or: .\run.ps1 -Port 9000

# 4. Open the dashboard and sign in
#    http://127.0.0.1:8899
#    admin password: data/initial_admin_password.txt (generated on first run; delete the file after login)
#
# If the browser ever shows a stale page, hard-refresh with Ctrl+F5.
```

Optional `.env`: copy `.env.example` to `.env`. Adding `OPENAI_API_KEY` (or `ANTHROPIC_API_KEY`) enables real-provider targets — a target only becomes **operational** after a passing connection test.

## Quickstart (Docker Compose)

```bash
cp .env.example .env   # set GX_ADMIN_PASSWORD, optionally provider keys
docker compose up --build
# dashboard: http://localhost:8000   (PostgreSQL storage, production-mode headers)
```

## What it does

| Module | Where | What to verify |
|---|---|---|
| Adapter framework | `app/adapters/` | `GET /api/v1/adapters`; target connection test marks operational **only** on real success |
| Scenario engine | `app/scenarios/library.py` | 14 builtin scenarios across injection / jailbreak / tool / RAG / policy / multimodal |
| Experiment orchestrator | `app/experiments/orchestrator.py` | authorization, replays, timeouts, cancellation, emergency stop |
| Policy engine (PDP) | `app/policy/engine.py` | deny > require_approval > allow; unknown tools fail closed; conflict detection |
| Enforcement gateway (PEP) | `app/tools/gateway.py` | **every** tool action passes it; sandbox escape refused; approvals held |
| Evaluator + findings | `app/experiments/evaluator.py`, `findings.py` | deterministic outcomes; model vs agent vs enforcement failure layers |
| Verification & regression | `findings.verify_finding` | evidence re-derived from stored events; confirmed → regression scenario |
| Benchmarks | `app/benchmarks/runner.py` | documented metrics with explicit numerators/denominators |
| Observability | `app/observability/` | correlated events, secret redaction, SSE stream |
| Dashboard | `static/` | 9 pages, all wired to live endpoints |
| API | `app/api/v1/routes.py` | versioned REST, OpenAPI at `/api/docs` |

## Security model in one paragraph

The control plane (policy, approvals, experiments) is separate from the execution plane (sandboxed tool executor). A tested agent cannot modify its own permissions, rewrite the audit trail, or disable the gateway — it can only *propose* actions, and the gateway decides. Destructive tools are policy-denied by default; network egress requires human approval; there is no shell tool; `real` execution mode is limited to read-only access inside `data/sandbox/`. Everything else is labeled `simulated` in the trace.

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — modules, data flow, trade-offs
- [Threat model](docs/THREAT_MODEL.md) — trust boundaries, attack surfaces
- [Adapter guide](docs/ADAPTER_GUIDE.md) — adding providers/protocols
- [Scenario guide](docs/SCENARIO_GUIDE.md) — writing scenarios and evaluators
- [API](docs/API.md) + live OpenAPI at `/api/docs`
- [Security limitations](docs/SECURITY_LIMITATIONS.md) — known gaps, read before relying on results

## Test status

`67 passed` (pytest) — policy engine, gateway enforcement, adapters (incl. OpenAI-compatible over mocked HTTP), orchestrator E2E, findings/regression, benchmarks, RBAC, redaction, emergency stop. A **live-provider evaluation** was also executed against `gemini-flash-lite-latest` (Google's OpenAI-compatible endpoint): safety-core 0% injection success, tool-boundary suite produced 2 agent-layer findings where the real model attempted unauthorized actions and the enforcement gateway blocked both. See `docs/SAMPLE_REPORT.md` and `docs/SECURITY_LIMITATIONS.md`.
