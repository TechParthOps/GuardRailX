# GUARDRAIL-X

A universal, model-independent platform for **authorized** AI guardrail research, evaluation, and controlled bypass testing.

It evaluates how LLMs and agents respond to adversarial inputs, policy conflicts, tool-misuse attempts, and guardrail-circumvention techniques — inside an isolated, fail-closed execution environment with an **independent enforcement gateway** that never trusts the tested model's self-reports.

> **Scope & ethics.** GUARDRAIL-X exists to *discover, measure, reproduce, and remediate* guardrail weaknesses in environments you are authorized to test. It deliberately does not ship "universal off-switches" for third-party safety systems, authentication bypass, or unrestricted OS access. All scenario payloads use harmless synthetic objectives (canary markers, fixture files, non-routable URLs).

---

## Quickstart (local, no Docker)

```powershell
# 1. Python 3.11+ and install dependencies
pip install -r requirements.txt -r requirements-dev.txt

# 2. Run the automated test suite (128 tests incl. Playwright browser tests)
$env:PYTHONPATH = "<repo path>"; python -m pytest tests -q

# 3. Create the FIRST administrator (no default identity ships with the app)
python -m app.setup            # interactive: email + password
#    or via API: set GX_SETUP_TOKEN, then POST /api/v1/setup (one-time)

# 4. Start the platform (kills any previous instance on the port automatically)
.\run.ps1            # or: .\run.ps1 -Port 9000

# 5. Open the dashboard and sign in
#    http://127.0.0.1:8899
#    Users can self-register at #/signup (GX_ALLOW_SIGNUP, role: viewer; admins
#    grant roles afterwards). Demo data only when GX_SEED_DEMO_DATA=true.
#
# If the browser ever shows a stale page, hard-refresh with Ctrl+F5.
```

**Security posture (hardened release):** no default admin identity; Argon2id password hashing
with transparent legacy upgrade; effective-privilege ceiling on every credential (a scoped key
can never mint a wider one); project-level isolation on every resource route; SSRF allowlist for
provider endpoints with credential-host binding; honest benchmark states (`failed` when the
provider is unavailable); per-route auth rate limits; CSP and security headers. Full details:
[Security Audit Report](docs/SECURITY_AUDIT_REPORT.md), [Issue Register](docs/ISSUE_REGISTER.md).

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

Hardened release: **128 passed** (pytest, incl. Playwright browser tests) covering the policy engine, enforcement gateway, adapters (OpenAI-compatible over mocked HTTP), orchestrator E2E, findings/regression, benchmarks, RBAC, project isolation, SSRF boundaries, redaction, emergency stop, and real-browser workflows. Live-provider evidence: `docs/TEST_REPORT.md`, `docs/SAMPLE_REPORT.md`, `docs/SECURITY_LIMITATIONS.md`.