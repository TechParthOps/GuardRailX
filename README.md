# GUARDRAIL-X

A universal, model-independent platform for **authorized** AI guardrail research, evaluation, and controlled bypass testing.

It evaluates how LLMs and agents respond to adversarial inputs, policy conflicts, tool-misuse attempts, and guardrail-circumvention techniques — inside an isolated, fail-closed execution environment with an **independent enforcement gateway** that never trusts the tested model's self-reports.

> **Scope & ethics.** GUARDRAIL-X exists to *discover, measure, reproduce, and remediate* guardrail weaknesses in environments you are authorized to test. It deliberately does not ship "universal off-switches" for third-party safety systems, authentication bypass, or unrestricted OS access. All scenario payloads use harmless synthetic objectives (canary markers, fixture files, non-routable URLs).

---

## What it does

| Module | Where | What to verify |
|---|---|---|
| Adapter framework | `app/adapters/` | `GET /api/v1/adapters`; target connection test marks operational **only** on real success; outbound endpoints pinned and policy-checked |
| Scenario engine | `app/scenarios/library.py` | 14 builtin scenarios across injection / jailbreak / tool / RAG / policy / multimodal |
| Experiment orchestrator | `app/experiments/orchestrator.py` | authorization, replays, timeouts, cancellation, emergency stop, transient-failure retry |
| Policy engine (PDP) | `app/policy/engine.py` | deny > require_approval > allow; unknown tools fail closed; conflict detection |
| Enforcement gateway (PEP) | `app/tools/gateway.py` | **every** tool action passes it; sandbox escape refused; approvals held |
| Evaluator + findings | `app/experiments/evaluator.py`, `findings.py` | deterministic outcomes; model vs agent vs enforcement failure layers |
| Verification & regression | `findings.verify_finding` | evidence re-derived from stored events; confirmed → regression scenario |
| Benchmarks | `app/benchmarks/runner.py` | documented metrics with explicit numerators/denominators; honest `failed`/`completed_with_failures` states |
| Observability | `app/observability/` | correlated events, secret redaction, SSE stream |
| Accounts | `app/auth/`, `app/setup.py`, `app/mailer.py` | public signup (lowest-privilege role), Argon2id, API-key privilege ceilings, project isolation, SMTP token delivery |
| Dashboard | `static/` | 9 pages, all wired to live endpoints |
| API | `app/api/v1/routes.py` | versioned REST, OpenAPI at `/api/docs` (dev) |

## Requirements

- **Python 3.11+** (developed and tested on 3.11; other versions are untested)
- Windows, Linux, or macOS (PowerShell launcher is Windows-only; `uvicorn` works everywhere)
- Optional: Docker + Docker Compose (PostgreSQL deployment), Playwright + Chromium (browser tests)
- Optional: a real provider key (`OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` / `NVIDIA_API_KEY`) for live targets — **not** needed for tests

## Quickstart (local, no Docker)

```bash
# 1. Install dependencies
pip install -r requirements.txt -r requirements-dev.txt

# 2. Run the offline test suite (no API keys, no network)
python -m pytest tests -q --ignore=tests/test_browser_workflows.py

# 3. Create the FIRST administrator (no default identity ships with the app)
python -m app.setup            # interactive: email + password
#    or via API: set GX_SETUP_TOKEN, then POST /api/v1/setup (one-time)

# 4. Start the platform
#    Linux/macOS:  uvicorn app.main:app --port 8899
#    Windows:      .\run.ps1            (kills any previous instance on the port)
#                  .\run.ps1 -Port 9000

# 5. Open the dashboard and sign in:  http://127.0.0.1:8899
#    Users can self-register at #/signup (GX_ALLOW_SIGNUP, role: viewer; admins
#    grant roles afterwards). Demo data only when GX_SEED_DEMO_DATA=true.
```

Optional `.env`: copy `.env.example` to `.env`. Adding a real provider key enables live-provider targets — a target only becomes **operational** after a passing connection test.

**Security posture:** no default admin identity; Argon2id password hashing with transparent legacy upgrade; effective-privilege ceiling on every credential (a scoped key can never mint a wider one); project-level isolation on every resource route; SSRF allowlist for provider endpoints with connection-time IP pinning; honest benchmark states (`failed` when the provider is unavailable); per-route auth rate limits; CSP and security headers; production startup fails closed on insecure configuration. Full details: [Security Audit Report](docs/SECURITY_AUDIT_REPORT.md), [Issue Register](docs/ISSUE_REGISTER.md), [Security limitations](docs/SECURITY_LIMITATIONS.md).

## Quickstart (Docker Compose, PostgreSQL)

```bash
cp .env.example .env
# set GX_PG_PASSWORD, GX_SECRET_KEY, GX_CORS_ORIGINS, GX_SETUP_TOKEN
# production also needs: GX_EMAIL_MODE=smtp + GX_SMTP_HOST/GX_SMTP_FROM
docker compose up --build -d
docker compose exec app python -m app.setup   # first administrator
# dashboard: http://localhost:8000  ·  health: GET /api/v1/ready
```

Production startup **refuses** to boot with insecure configuration (missing
`GX_SECRET_KEY`, wildcard CORS, demo seeding, or missing SMTP delivery while
account-token workflows are enabled).

## Tests

| Group | Command | Needs |
|---|---|---|
| Offline unit/API/integration | `python -m pytest tests -q --ignore=tests/test_browser_workflows.py` | nothing (fake credentials injected by fixtures; DNS blocked when `GX_OFFLINE_TEST=1`) |
| Browser workflows | `pip install playwright && python -m playwright install chromium` then `python -m pytest tests/test_browser_workflows.py -q` | Playwright + Chromium |
| PostgreSQL migrations | `GX_TEST_PG_URL=postgresql+psycopg://... python -m pytest tests/test_db_migrations.py -q` | a disposable PostgreSQL (never production) |
| Full suite | `python -m pytest tests -q` | Playwright installed |

CI runs the offline suite, packaging rules, browser tests, and PostgreSQL
migrations as separate jobs (`.github/workflows/ci.yml`). The most recent
executed results live in [docs/TEST_REPORT.md](docs/TEST_REPORT.md).

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — modules, data flow, trade-offs
- [Threat model](docs/THREAT_MODEL.md) — trust boundaries, attack surfaces
- [Operations](docs/OPERATIONS.md) — deployment, configuration, troubleshooting, backup
- [Data model](docs/DATA_MODEL.md) · [API](docs/API.md) (live OpenAPI at `/api/docs` in development)
- [Adapter guide](docs/ADAPTER_GUIDE.md) · [Scenario guide](docs/SCENARIO_GUIDE.md)
- [Security audit report](docs/SECURITY_AUDIT_REPORT.md) · [Issue register](docs/ISSUE_REGISTER.md) · [Security limitations](docs/SECURITY_LIMITATIONS.md)
- [Test report](docs/TEST_REPORT.md) · [Sample report](docs/SAMPLE_REPORT.md) (labeled demo data)

## Current limitations

Single-process deployment (in-memory rate limiting + SSE bus — run one worker);
account-token delivery via SMTP only (no email API providers yet); real network
egress intentionally unimplemented in the tool executor (approved actions run
simulated); no encryption at rest. Full list: `docs/SECURITY_LIMITATIONS.md`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md) — no public issues for vulnerabilities.

## License

[MIT](LICENSE) — provisionally selected for the initial public release; the
owner may relicense before external contributions arrive (note inside
`LICENSE`).
