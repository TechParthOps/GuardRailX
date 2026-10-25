# GUARDRAIL-X — Test Execution Report (final remediation release)

- Date: 2026-10-25
- Commands:
  - `python -m pytest tests -q` → **193 passed, 0 failed, 0 skipped**
  - `GX_OFFLINE_TEST=1 python -m pytest tests -q --ignore=tests/test_browser_workflows.py`
    → **189 passed, 0 failed** (DNS fully disabled in tests — Phase 9 offline gate)
- Result: **193 passed / 0 failed / 0 skipped**; offline variant **189 / 0 / 0** (4 browser
  tests excluded from the offline runner; they bind only to 127.0.0.1).

## Suites

| Suite | Tests | Scope |
|---|---|---|
| test_policy_engine | 9 | PDP semantics, deny-dominance, conflicts, fail-closed |
| test_gateway | 8 | PEP: deny, approval hold, containment, dry-run, fail-closed |
| test_adapters | 11 | OpenAI-compatible (mocked transport), registry fail-closed |
| test_adapters_anthropic | 19 | Full mocked lifecycle incl. transient classification, size caps, header handling |
| test_netguard_transport | 11 | Pinned transport: DNS rebinding, IPv6/mapped, redirects, local opt-in, credential binding |
| test_db_migrations | 9 | REAL PostgreSQL: fresh init, v1→v2 upgrade (PG + SQLite), retry, concurrency, FK/uniqueness |
| test_email_delivery | 11 | SMTP capture server, failure paths, atomic token consumption (8-way concurrency) |
| test_setup_and_admin | 10 | Atomic bootstrap (6 concurrent), last-admin protection, audit of rejections |
| test_body_limits | 5 | Declared/streamed/malformed/near-limit/413 headers |
| test_evaluator, test_experiments_e2e, test_benchmarks, test_security, test_dashboard, test_pentest_* | 80 | Previously established coverage, all green |
| test_browser_workflows | 4 | Real Chromium: signup→login→dashboard→signout, XSS non-execution, empty login form, invalid-login error |

## PostgreSQL verification (Phases 2 + 13)

- Real PostgreSQL 16 container: fresh init, upgrade from v1.0 schema (PG and SQLite variants),
  retry-after-interrupt, 4-way concurrent migrate (advisory lock), FK + uniqueness enforcement.
- **Docker Compose production stack**: `docker compose up --build` → PostgreSQL healthy →
  app migrated → first-admin setup → signup → project → mock target → experiment
  `completed` with `model_violation` → finding `regression_tested` (evidence: compose logs +
  API responses). Previously this flow crashed with `StringDataRightTruncation` (R14).

## Security boundaries re-verified

- PoC battery (`scripts/poc_baseline.py`): **0/10 vulnerable** (all GX-001…GX-010 remediations hold).
- Offline gate: full suite passes with DNS resolution blocked.

## Release artifact

- `scripts/make_release.py` → `dist/guardrailx-release.zip`, verification PASS:
  no `.git`/caches/databases/secrets/PID/backups; all required files present;
  `.env.example` contains no secret values.
