# API (v1)

Interactive OpenAPI: `/api/docs` (served by the app). Base path `/api/v1`.
Authentication: `Authorization: Bearer <token>` (session token from `/auth/login`
or `gx_...` API key from `/auth/api-keys`).

## Endpoints by module

| Group | Endpoints |
|---|---|
| System | `GET /health`, `GET /ready` |
| Auth | `POST /auth/login`, `POST /auth/logout`, `GET /auth/me`, `POST /auth/users` (admin), `POST/GET/DELETE /auth/api-keys` |
| Projects | `GET/POST /projects` |
| Targets | `GET/POST /targets`, `GET /adapters`, `POST /targets/{id}/test-connection`, `DELETE /targets/{id}` |
| Policies | `GET/POST /policies`, `POST /policies/{id}/activate` (admin), `POST /policies/evaluate` (dry-run), `GET /policies/{id}/conflicts` |
| Scenarios | `GET /scenarios?category=`, `GET /scenarios/categories`, `POST /scenarios` |
| Experiments | `POST /experiments`, `POST /experiments/{id}/start`, `GET /experiments/{id}`, `POST /experiments/{id}/cancel`, `GET /experiments/{id}/events`, `GET /experiments/{id}/trace-analysis` |
| Approvals | `GET /approvals/pending`, `POST /approvals/{id}/decide` (admin) |
| Findings | `GET /findings`, `GET /findings/{id}`, `POST /findings/{id}/verify` |
| Red team | `POST /redteam/variations`, `POST /redteam/remediation?experiment_id=` |
| Benchmarks | `GET /benchmarks/suites`, `POST /benchmarks/run` (blocking), `GET /benchmarks` |
| Observability | `GET /events?type=&level=`, `GET /events/stream` (SSE) |
| Admin | `POST /admin/emergency-stop`, `GET /admin/audit` (admin), `GET /admin/stats` |

## Key semantics

- **403** on missing authorization acknowledgement, unverified targets, inactive policies.
- **423** when emergency stop is active.
- `POST /policies/evaluate` is a pure PDP dry-run (no execution).
- Approved actions execute in the experiment's gateway mode; the trace records
  `mode: simulated|real` — simulated actions are never reported as real.
- Error shape: `{"detail": "..."}`; validation errors are FastAPI 422s.

## Example: run an authorized evaluation

```bash
TOKEN=$(curl -s -X POST localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@guardrailx.local","password":"..."}' | jq -r .access_token)

EXP=$(curl -s -X POST localhost:8000/api/v1/experiments -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{
    "project_id":"prj_...","target_id":"tgt_...","policy_id":"pol_...",
    "scenario_keys":["inj.direct.override"],
    "authorization":{"authorized_by":"alice","acknowledged":true,"scope":"lab"},
    "config":{"replays":2}}' | jq -r .id)

curl -s -X POST localhost:8000/api/v1/experiments/$EXP/start -H "Authorization: Bearer $TOKEN"
curl -s localhost:8000/api/v1/experiments/$EXP -H "Authorization: Bearer $TOKEN" | jq .stats
```
