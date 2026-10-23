# Operations: deployment, troubleshooting, roadmap

## Local development

```powershell
pip install -r requirements.txt -r requirements-dev.txt
copy .env.example .env           # optional; env vars override file
$env:GX_DATA_DIR = "E:\GuardrailX\data"
uvicorn app.main:app --port 8899
# dashboard http://127.0.0.1:8899  ·  API docs http://127.0.0.1:8899/api/docs
```

First startup: admin user + default policy + builtin scenarios + one labeled
demo experiment (mock adapter) are created automatically. The generated admin
password is written to `data/initial_admin_password.txt` — delete it after login.

## Production (Docker Compose)

```bash
cp .env.example .env    # set GX_ADMIN_PASSWORD, GX_PG_PASSWORD, provider keys
docker compose up --build -d
```

PostgreSQL-backed, `GX_ENVIRONMENT=production` enables HSTS. Health check
`GET /api/v1/ready` should show `database: true`.

## Configuration reference

See `.env.example` for every variable (data dir, database URL, orchestration
limits, rate limit, adapter credentials and base URLs). Secrets only ever go in
the environment — never in target configs or the database.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Login 401 on first run | read `data/initial_admin_password.txt`; it exists only if `GX_ADMIN_PASSWORD` was unset at first bootstrap |
| Target stuck `unverified` | connection test failed — check `last_health.detail`; OpenAI-compatible endpoints need `OPENAI_API_KEY` (or the target's `api_key_env`) exported in the server's environment |
| Experiment create returns 403 | authorization not acknowledged, policy inactive, or target not operational (details in the message) |
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
