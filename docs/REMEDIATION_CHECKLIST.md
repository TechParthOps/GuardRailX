# Remediation checklist — final release blockers (Phase 1)

Baseline: commit `7835219`, **128 passed / 0 failed / 0 skipped** (this environment has DNS;
the reported 6 failures/4 skips in the audit environment were DNS-dependent tests — fixed in Phase 9).

| # | Phase | Defect (verified before fixing) | Files | Regression test | Status |
|---|---|---|---|---|---|
| R1 | 2.1 | PostgreSQL driver absent while compose URL uses psycopg2 | `requirements.txt`, `docker-compose.yml`, `app/config.py` | `tests/test_db_migrations.py::test_compose_url_driver_matches_requirements` | done |
| R2 | 2.2 | Migration 1 uses SQLite-only SQL (`INSERT OR IGNORE`, `randomblob`); fails on PostgreSQL | `app/db.py` | `tests/test_db_migrations.py` (pg + sqlite upgrade scenarios) | done |
| R3 | 2.2 | No migration locking (concurrent workers) / no interrupted-migration retry safety | `app/db.py` | `tests/test_db_migrations.py::test_migration_retry_and_lock` | done |
| R4 | 3 | Anthropic adapter: `NameError: EndpointPolicyError` on every health check (missing imports) | `app/adapters/anthropic.py` | `tests/test_adapters_anthropic.py` (12 mocked tests) | done |
| R5 | 4 | DNS rebinding: validation resolves DNS, then httpx resolves DNS *again* at connect time | `app/adapters/netguard.py`, both adapters | `tests/test_netguard_transport.py` (pinned-IP transport + rebinding simulation) | done |
| R6 | 5 | `_deliver_account_token` discards tokens (no delivery); reset/verification unusable in production | `app/api/v1/routes.py`, `app/mailer.py` (new), `app/config.py` | `tests/test_email_delivery.py` (SMTP capture server + concurrency) | done |
| R7 | 5 | Account tokens consumable twice under concurrency (read-then-write) | `app/auth/service.py::consume_user_token` | `tests/test_email_delivery.py::test_reset_token_single_use_concurrent` | done |
| R8 | 6 | `setup/status` uses any-user count vs setup handler admin count → disagree when a viewer registers pre-setup; non-atomic bootstrap | `app/setup.py`, `routes.py` | `tests/test_setup_atomicity.py` | done |
| R9 | 7 | Last active administrator can be demoted/disabled → lockout | `routes.py` change_role/disable_user | `tests/test_last_admin.py` | done |
| R10 | 8 | Body-size guard trusts Content-Length; chunked bodies unbounded | `app/main.py` | `tests/test_body_limits.py` | done |
| R11 | 9 | Security tests depend on real DNS/internet | multiple test files | full suite green with DNS disabled | done |
| R12 | 11 | Multi-worker claim vs in-memory limiter/bus | `docs/OPERATIONS.md`, `app/main.py` (startup warning) | documented single-process constraint | done |
| R13 | 12 | Release ZIP contained .git, caches, DBs, secrets, backups | `scripts/make_release.py` (new) | packaging verification in script output | done |
| R14 | 13 | **PostgreSQL-only crash**: `findings.likelihood` (20-char value) overflowed `VARCHAR(12)`; `benchmark_runs.status` would overflow `VARCHAR(16)` with `completed_with_failures` — SQLite does not enforce lengths, PostgreSQL does → every real-provider case became `infra_error` in the compose deployment | `app/models.py`, `app/db.py` (migration 2, PG `ALTER COLUMN TYPE`) | E2E against real PG: experiment `completed`, finding `regression_tested`; `test_db_migrations.py` fresh-DB asserts migrations 1+2 | done |
