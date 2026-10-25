# GUARDRAIL-X — Test Execution Report (public-release readiness)

- Date: 2026-10-25
- Platform: Windows 11, Python 3.11.9
- All counts below come from the exact commands listed and are reproducible.

## Stage B — Offline suite (mandatory CI gate)

Command: `python -m pytest tests -q --no-header --ignore=tests/test_browser_workflows.py`
Environment: no real provider credentials (fixtures inject clearly-fake values;
`OPENAI_API_KEY=""` explicitly set to simulate a clean machine — same result).
Result: **202 passed, 0 failed, 0 skipped** (~50 s).

Clean-environment proof: with `OPENAI_API_KEY=""`/`ANTHROPIC_API_KEY=""`,
`pytest tests/test_adapters.py tests/test_adapters_anthropic.py -q` → **34 passed**
(previously 4 failed on a clean machine; fixed by the `_offline_provider_credentials`
fixture).

Offline/DNS-blocked run: `GX_OFFLINE_TEST=1` with the same selection →
**202 passed** (the conftest guard fails any test that attempts real DNS).

## Stage C — Browser tests

Command: `python -m pytest tests/test_browser_workflows.py -q`
Requires: `pip install playwright && python -m playwright install chromium`.
Result: **4 passed** (signup→login→dashboard→sign-out, XSS non-execution,
empty login form, invalid-login error) against a real Chromium via a live
uvicorn subprocess.

## Stage D — PostgreSQL / Docker

Command: `python -m pytest tests/test_db_migrations.py -q` with a disposable
PostgreSQL 16 container (`GX_TEST_PG_URL` env var).
Result: **9 passed** — fresh init, v1→v2 upgrade (PG + SQLite), retry-after-interrupt,
4-way concurrent migrate, FK/uniqueness, membership preservation.

Docker Compose end-to-end: `docker compose up --build -d` with production env →
healthy → first-admin setup → researcher workflow → experiment `completed`
(`model_violation`) → finding `regression_tested` on PostgreSQL. Verified this
release cycle.

## Stage E — Release candidate

Command: `python scripts/make_release.py`
Result: built from committed HEAD on a clean tree; **verification PASS**
(116+ entries, single top-level dir, no prohibited artifacts, all required
files, no nested archives, `.env.example` free of secret values, SHA-256 written).
Extraction smoke test: unzipped into a fresh temp dir → offline suite from the
extracted source → **202 passed** (proves no dependency on the developer's workspace).

## Security verification

`python scripts/poc_baseline.py` → **0/10 vulnerabilities reproducible**
(all GX-001…GX-010 remediations hold), plus the Priority-0 delivery suite
(13 tests) covering production fail-closed behavior.

## Known limitations of the test setup

- Browser tests need Playwright + Chromium installed locally (documented; run independently).
- PostgreSQL tests need a disposable container; `GX_TEST_PG_URL` selects it. Never point them at production.
- Live-provider calls are NOT part of any automated suite; exercise them manually with your own keys.
