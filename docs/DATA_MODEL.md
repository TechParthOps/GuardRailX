# Data model

Authoritative definition: `app/models.py` (SQLAlchemy 2.0 typed columns).
Migrations: `app/db.py::migrate()` — creates the full schema, then applies any
incremental migrations listed in `MIGRATIONS` and stamps `schema_migrations`.
JSON columns are used only where provider/trace/policy schemas are genuinely
variable; everything else is typed with indexes and foreign keys.

| Table | Purpose | Key columns / notes |
|---|---|---|
| `users` | identities | unique email, PBKDF2 `password_hash`, role (admin/researcher/viewer) |
| `auth_tokens` | sessions + API keys | `token_hash` only (HMAC w/ server secret), kind, role, expiry, revocable |
| `audit_events` | administrative audit trail | actor, action, object, redacted detail JSON |
| `projects` | grouping | `is_demo` flag for labeled demo data |
| `targets` | registered model endpoints | adapter, model, non-secret config JSON, status (`unverified`→`operational`/`failed`), last health |
| `policies` | versioned policy documents | (name, version) unique, `active` flag, document JSON, hash computed on read |
| `scenarios` | scenario library | key PK, category, template JSON contract, risk, source (builtin/custom/regression), `origin_finding_id` |
| `experiments` | runs | authorization record, config (replays/dry_run/gateway mode), status machine, stats, adapter+policy version stamps |
| `cases` | per-scenario-replay records | seq, trace_id, outcome JSON (markers, checks, gateway results), finding link |
| `events` | durable event store | experiment/case/trace correlation, seq, type, actor, level, redacted payload JSON |
| `approvals` | human approval gate | tool + arguments snapshot, pending→approved/denied, decided_by/at |
| `findings` | finding lifecycle | class, severity ≠ confidence, expected vs observed, evidence event ids, reproduction recipe, `failure_layer` (model/agent/enforcement), `reproducible` |
| `regressions` | generated regression tests | finding FK, scenario key, template snapshot |
| `benchmark_runs` | suite executions | suite key, persisted metrics JSON with numerator/denominator |

## Integrity rules

- Only hashes of credentials/tokens are stored; target config rejects secret-named fields at the schema layer.
- `events.payload` and audit details pass through `redact_obj` before persistence.
- Deleting a target cascades nothing (historical experiments keep IDs for evidence integrity).
- WAL + `busy_timeout=10000` for SQLite; `foreign_keys=ON` enforced.
- Retention/backup: not automated — copy the data directory (SQLite) or use standard `pg_dump` (PostgreSQL). Integrity check: `PRAGMA integrity_check` / restore drill.
