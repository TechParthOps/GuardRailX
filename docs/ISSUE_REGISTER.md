# GUARDRAIL-X — Security Issue Register (pre-hardening audit)

Baseline: commit `dbc5150` ("baseline: pre-hardening snapshot"), 71/71 tests passing.
All findings reproduced with `scripts/poc_baseline.py` + `scripts/poc_gx004.py`
against an isolated temp database. Status values: `open` → `fixing` → `fixed (regression test passing)`.

| ID | Severity | Confidence | Component | Title | Status |
|---|---|---|---|---|---|
| GX-001 | **critical** | high | `app/auth/service.py::create_api_key` | API-key privilege escalation: viewer-scoped key mints admin key | fixed |
| GX-002 | **critical** | high | all resource routes | IDOR: no project isolation — any authenticated user can read/use any project, target, experiment, finding, event by ID | fixed |
| GX-003 | **critical** | high | `app/adapters/openai_compatible.py` | SSRF (arbitrary `base_url` incl. loopback/metadata) + arbitrary env-var credential selection (`api_key_env` reads any env var and sends it to the attacker's endpoint) | fixed |
| GX-004 | high | high | `app/benchmarks/runner.py`, `app/api/v1/routes.py::run_benchmark` | Benchmark reported `completed` (HTTP 200) with 100% provider failures; no partial-failure state | fixed |
| GX-005 | high | high | `app/config.py`, `app/seed.py` | Documented default admin identity (`admin@guardrailx.local`) + generated password written to file; no first-run setup flow | fixed |
| GX-006 | medium | high | `app/main.py::lifespan` | Startup auto-seeds demo project + runs demo experiment (also in production) | fixed |
| GX-007 | high | high | `app/auth/service.py::resolve_token` | Token role frozen at issuance: demoted/disabled-role users keep old privileges until token expiry; no revocation on role change/password change | fixed |
| GX-008 | medium | high | `app/api/v1/routes.py::stats` | `/admin/stats` (global cross-project metrics) readable by viewers/researchers; audit properly 403 | fixed |
| GX-009 | high | high | `app/api/v1/routes.py` | No public registration endpoint or UI | fixed |
| GX-010 | low | high | `app/main.py` | `/api/docs` + `/api/openapi.json` exposed unauthenticated (full route map) | fixed (config-gated) |

## Suspected / proactively remediated (not independently reproduced as failures)

| ID | Severity | Component | Note |
|---|---|---|---|
| GX-011 | medium | `app/auth/service.py` | PBKDF2-SHA256 (240k) acceptable but Argon2id preferred; migrated with transparent hash upgrade on login |
| GX-012 | medium | all write routes | Mass assignment: request models now `extra="forbid"` |
| GX-013 | medium | `app/main.py` | No CSP header; added strict CSP + additional headers |
| GX-014 | high | auth endpoints | No per-route rate limiting on login/signup/reset (global limiter only) |
| GX-015 | medium | frontend | Login form pre-filled default admin email; removed |
| GX-016 | low | packaging | Runtime secrets/DB/PID files present in working tree; excluded via `.gitignore` + removed from git tracking; cleanup utility added |
| GX-017 | medium | `app/experiments/orchestrator.py` | No retry/backoff for transient provider failures (429/5xx); added bounded retry honoring Retry-After |
| GX-018 | medium | redirects | httpx default follows redirects blindly; SSRF-guard re-validates each hop, redirects disabled by default |

## Explicitly verified NOT vulnerable

- SQL injection: all queries via SQLAlchemy ORM/parameterized; no string-built SQL.
- Password/token storage: hashes only (now Argon2id/PBKDF2 + HMAC-SHA256 token hashes); constant-time comparisons used.
- Secret redaction in events/audit/logs: regression-tested (`test_redact*`).
- Reflected XSS in API responses: JSON only; frontend escapes via `esc()` (regression-tested in dashboard tests).
- Approval gate / policy gateway fail-closed semantics: previously regression-tested; extended in pen-test suite.
