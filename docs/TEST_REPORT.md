# GUARDRAIL-X — Test Execution Report (hardening release)

- Date: 2026-10-23
- Command: `python -m pytest tests -q`
- Result: **128 passed, 0 failed, 0 errors** (≈28 s)

## Suites

| Suite | Tests | Scope |
|---|---|---|
| `test_policy_engine.py` | 9 | PDP semantics, deny-dominance, conflicts, fail-closed |
| `test_gateway.py` | 8 | PEP: deny, approval hold, containment, dry-run, fail-closed |
| `test_adapters.py` | 11 | Mock determinism, OpenAI-compatible HTTP (mocked transport), registry fail-closed |
| `test_evaluator.py` | 9 | Deterministic outcomes, layer separation |
| `test_experiments_e2e.py` | 8 | Authorization gates, findings, regression, approvals, persistence |
| `test_benchmarks.py` | 4 | Documented metrics, suite resolution, honest states |
| `test_security.py` | 12 | RBAC, redaction, emergency stop, API-key lifecycle |
| `test_dashboard.py` | 4 | SPA parse check, asset serving, security headers |
| `test_pentest_auth.py` | 16 | GX-001 ceiling, revocation, demotion, signup, reset, Argon2, rate limit |
| `test_pentest_isolation.py` | 10 | Cross-project IDOR, membership, scoped keys, scoped summaries |
| `test_pentest_boundary.py` | 14 | SSRF, input handling, anonymous surface, headers, docs gating, gateway boundary |
| `test_browser_workflows.py` | 4 | Real Chromium: signup→login→dashboard→signout, XSS non-execution, empty login form |

## Browser workflows actually executed (Playwright + Chromium)

1. Login page renders with an EMPTY email field (no default identity) and a working signup link.
2. Full workflow: signup → verification-optional login → dashboard renders scoped data → sign-out clears session.
3. Stored XSS payload (`<img onerror=...>`) rendered as text; `window.__xss` never set.
4. Invalid login shows the generic error and stays on the login page.

## Vulnerability reproduction (PoC)

`scripts/poc_baseline.py` — before remediation: 8/10 CONFIRMED. After: **0/10 vulnerable**
(GX-010's remaining "exposure" is development-by-design; production returns 404 for docs/openapi —
verified in `test_openapi_disabled_in_production`).

`scripts/poc_gx004.py` — before: benchmark `completed` with infra_error_rate 1.0 (CONFIRMED).
After: status `failed`.

## Cleanup utility (executed on real data)

`scripts/cleanup_demo_data.py --execute --backup ... --revoke-all-credentials`:
348 demo records deleted, backup written, 17 stale credentials revoked,
builtin scenarios (14) + default policy + user accounts preserved.

## Live-provider verification (earlier release evidence, still valid)

Live evaluation against `gemini-flash-lite-latest` executed real experiments:
safety-core 0% injection success; tool-boundary produced 2 agent-layer findings where the
model attempted unauthorized actions and the enforcement gateway blocked both. Provider
quota/EOL failures on OpenAI/NVIDIA were honestly recorded as `infra_error` (never bypasses).
