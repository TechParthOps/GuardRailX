# Operations: deployment, troubleshooting, roadmap

## Local development

```powershell
pip install -r requirements.txt -r requirements-dev.txt
copy .env.example .env           # optional; env vars override file
python -m app.setup              # create the FIRST administrator (interactive)
.\run.ps1                        # serves on http://127.0.0.1:8899
# dashboard http://127.0.0.1:8899  ·  API docs http://127.0.0.1:8899/api/docs
```

First startup: **no default administrator exists** — create it with `python -m app.setup`
or the one-time `POST /api/v1/setup` endpoint (gated by `GX_SETUP_TOKEN`). Built-in
scenarios and the default fail-closed policy are created automatically. Demo data
**only** when `GX_SEED_DEMO_DATA=true` (never enable in production). Users self-register
via the signup page (`GX_ALLOW_SIGNUP`) and receive the lowest-privilege role; admins
promote users under `GET/POST /api/v1/admin/users`. Credential reset for an existing
account: `python -m app.setup --reset-password`.

## Production (Docker Compose)

```bash
cp .env.example .env    # set GX_PG_PASSWORD, GX_SECRET_KEY, GX_CORS_ORIGINS, GX_SETUP_TOKEN
docker compose up --build -d
docker compose exec app python -m app.setup    # first administrator
```

Production startup **refuses** insecure configuration (missing `GX_SECRET_KEY`,
wildcard `GX_CORS_ORIGINS`, or `GX_SEED_DEMO_DATA=true`). Docs/OpenAPI are disabled
in production by default. Health check: `GET /api/v1/ready` → `{"database": true}`.
Database port is not published to the host; the app container runs non-root.

## Configuration reference

See `.env.example` for every variable (data dir, database URL, orchestration
limits, rate limit, adapter credentials and base URLs). Secrets only ever go in
the environment — never in target configs or the database.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| No administrator can sign in | run `python -m app.setup` (first admin) or `--reset-password` for an existing account |
| Target stuck `unverified` | connection test failed — check `last_health.detail`; OpenAI-compatible endpoints need `OPENAI_API_KEY` (or the target's `api_key_env`) exported in the server's environment |
| Experiment create returns 403/404 | authorization not acknowledged, policy inactive, target not operational, or resource outside your project scope (404 = anti-enumeration) |
| Experiment create returns 423 | emergency stop active (`POST /admin/emergency-stop {"active":false}` to clear, admin only) |
| `database is locked` (SQLite) | multiple writers on the same file; prefer PostgreSQL for concurrent use |
| Port already in use (`[Errno 10048]`) | a previous instance is still listening — use `.\run.ps1`, which stops it automatically, or pick another port (`.\run.ps1 -Port 9000`) |
| Dashboard stuck on "Loading…" | stale or failed JavaScript — hard-refresh with **Ctrl+F5**; if you edited `static/app.js`, verify it parses: `node --check static/app.js` |
| Benchmarks empty | suite resolves scenarios from the DB; ensure bootstrap ran (scenarios listed under `GET /scenarios`) |
| Dashboard shows no data | all pages read live API data; check you are logged in and that a demo/experiment exists |

## Security operations

- **Emergency stop**: `POST /api/v1/admin/emergency-stop {"active": true}` (admin). Freezes new + running experiments immediately.
- **Secrets**: rotate by revoking API keys (`DELETE /auth/api-keys/{id}`); provider keys live outside the platform entirely.
- **Audit**: `GET /api/v1/admin/audit` (admin) records logins, policy changes, approvals, target changes.
- **Backup/restore**: stop the app; copy `data/` (SQLite) or `pg_dump`; restore on a clean volume and run integrity check before serving.

## Roadmap

1. **Adapter expansion**: agent-framework runners (LangGraph/AutoGen/MCP) exposing agent actions as gateway-mediated tool calls; browser/computer-use agents with screenshot-only evidence channel; multimodal (image/audio) fixture support gated on declared modalities.
2. **Execution plane hardening**: container-per-experiment sandbox (gVisor/Firecracker), egress allowlist proxy for approved network actions, encrypted evidence-at-rest.
3. **Scale-out**: Redis-backed event bus + rate limiter, queue-based orchestration for multi-node, Alembic migration chain as schema growth demands.
4. **Evaluation science**: LLM-assisted semantic verification (currently deterministic-only), statistical confidence intervals, multi-turn stateful scenario DSL, cross-model comparison dashboards.
5. **Compliance**: signed export bundles (evidence chain), retention policies, SSO/OIDC auth backend.

## Account and credential management (hardened release)

- **First admin**: `python -m app.setup` (CLI) or `POST /api/v1/setup` with `GX_SETUP_TOKEN` (one-time; refused after the first admin exists).
- **Role changes**: `POST /api/v1/admin/users/{id}/role` � effective immediately on all the user's credentials; optionally revokes them.
- **Disable account**: `POST /api/v1/admin/users/{id}/disable` � sign-in refused and live sessions invalidated instantly.
- **Password policy**: 12+ chars with upper/lower/digit; Argon2id storage; legacy PBKDF2 hashes upgrade transparently at next login.
- **API keys**: ceiling-enforced (`role` + `scopes`); a key can never mint a credential above its own effective privileges; shown exactly once.
- **Email verification / password reset**: configure `GX_EMAIL_MODE=smtp` + `GX_SMTP_HOST`/`GX_SMTP_FROM` for production. Console delivery (raw tokens to stdout) is development-only and hard-refused in production. Disable self-serve reset with `GX_ALLOW_PASSWORD_RESET=false` if you run without SMTP.
- **Demo data removal**: `python scripts/cleanup_demo_data.py --dry-run` then `--execute --backup <file> [--revoke-all-credentials]`.

## Deployment model (Phase 11): single-process by design

The current release is a **single-process deployment**:

- Rate limiting (global + per-auth-route) is in-memory per process.
- The SSE live-event bus is in-memory per process.
- Experiment execution runs as asyncio tasks inside the serving process.

Run exactly ONE uvicorn worker (default of `run.ps1` / compose `CMD`). Running
`--workers N > 1` or multiple replicas gives inconsistent rate limits, missing
live events, and duplicated experiment tasks � the app logs a warning at startup
if it detects a multi-worker environment via `GX_EXPECTED_WORKERS`.

Scaling out is a roadmap item (Redis-backed limiter/bus + queue-based
orchestration, see the original roadmap in this document) and requires tests
proving throttling, authorization, and event delivery remain correct across
workers before any horizontal-scalability claim.

Reverse-proxy guidance: terminate TLS, forward `X-Forwarded-For` ONLY from
trusted proxies, and apply proxy-level body-size limits as defense in depth
(the app enforces its own 1 MiB cap independently).