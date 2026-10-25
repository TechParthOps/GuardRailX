# GUARDRAIL-X — Security Audit Report (hardening release)

- Audit object: supplied repository at baseline commit `dbc5150`
- Method: static review + dynamic reproduction (PoC scripts against isolated temp DB) + regression tests
- Result: **8 confirmed vulnerabilities, all remediated with regression tests (audit-time baseline; current suite: see docs/TEST_REPORT.md — counts evolve as coverage grows and are not restated here to avoid stale claims)**

## Confirmed findings

| ID | Severity | Finding | Root cause | Fix | Regression test |
|---|---|---|---|---|---|
| GX-001 | critical | Viewer-scoped API key minted an administrator key | `create_api_key` defaulted the new key's role to the **account's** role, not the credential's effective role | Effective-privilege ceiling: role ceiling + scope subset enforcement + audit on attempts (`app/auth/service.py`) | `tests/test_pentest_auth.py::test_viewer_key_cannot_create_any_key`, `test_researcher_cannot_mint_admin_key`, `test_nested_key_creation_respects_ceiling`, `test_escalation_attempts_are_audited` |
| GX-002 | critical | IDOR: cross-project read/use of any target/experiment/finding/event/benchmark by ID | No resource-level authorization anywhere | Project ownership + `project_members` + scope grants; central `project_access()` applied to every resource route; 404 (not 403) on foreign resources; cross-project resource combos rejected | `tests/test_pentest_isolation.py` (9 tests) |
| GX-003 | critical | SSRF via arbitrary `base_url` + arbitrary env-var credential selection sent as Bearer to attacker endpoint | No endpoint policy; `api_key_env` accepted any env name | `app/adapters/netguard.py`: scheme/userinfo/fragment rules, admin allowlist + trusted-credential host binding, DNS+IP validation (loopback/private/link-local/metadata), local-endpoint opt-in; enforced at **registration** (`validate_config_secure`) and per request; redirects re-validated | `tests/test_pentest_boundary.py::test_ssrf_*` (6), `test_target_registration_blocks_ssrf_endpoints` |
| GX-004 | high | Benchmark reported `completed` (HTTP 200) with 100% provider failures | Status set unconditionally | Distinct states: `completed` / `completed_with_failures` / `failed` / `cancelled`; metrics computed on applicable cases with `infra_error_rate` exposed | `test_provider_429_benchmark_not_completed`, `test_infra_errors_never_become_findings` |
| GX-005 | high | Documented default admin identity + generated password written to file | Auto-bootstrap of `admin@guardrailx.local` | No default identity; one-time setup via CLI (`python -m app.setup`) or `POST /api/v1/setup` gated by `GX_SETUP_TOKEN`; refused once an admin exists; audited | `tests/test_pentest_auth.py::test_setup_flow_one_time_and_token_gated`; browser `test_login_page_renders_and_signup_link` (empty email field) |
| GX-006 | medium | Startup auto-seeded demo project + experiment in every environment | Unconditional lifespan seeding | `GX_SEED_DEMO_DATA` (default false; production refuses true) | `scripts/poc_baseline.py` GX-006 check; production check in `test_openapi_disabled_in_production` setup |
| GX-007 | high | Stale token privileges after role demotion / disablement | Role frozen on the token at issuance | Effective role = min(current account role, credential ceiling), computed per request; disablement → 401 immediately; admin role-change/disable/revocation endpoints | `test_role_demotion_invalidates_effective_privileges`, `test_disabled_user_credentials_rejected_immediately` |
| GX-008 | medium | Global platform statistics readable by viewers | `/admin/stats` only required viewer | `/admin/stats` admin-only; new scoped `/dashboard/summary` | `test_admin_routes_require_admin`, `test_dashboard_summary_scoped` |

## Proactively remediated (suspicion → verified fix)

| ID | Note | Test |
|---|---|---|
| GX-009 | No public registration: added `POST /auth/signup` (lowest-privilege role only, policy-enforced, rate-limited, generic duplicate handling) + UI | `test_signup_*` (4), browser signup workflow |
| GX-010 | Docs/OpenAPI exposure: disabled in production by default (`GX_ENABLE_DOCS` override) | `test_openapi_disabled_in_production` |
| GX-011 | PBKDF2 → Argon2id with transparent upgrade on login | `test_argon2id_upgrade_on_login` |
| GX-012 | Mass assignment: all request models `extra="forbid"` | `test_signup_rejects_role_field_and_duplicates` |
| GX-013 | Strict CSP + Permissions-Policy headers; no inline scripts | `test_security_headers_present` |
| GX-014 | Per-route auth rate limits (login/signup/verify/reset) + audit on limit | `test_auth_rate_limit` |
| GX-015 | Login form pre-filled default email removed | browser test (empty field assertion) |
| GX-016 | Runtime artifacts (DB, secret_key, password file, PID) excluded via `.gitignore` + removed from git tracking; cleanup utility | `scripts/cleanup_demo_data.py` executed on real data (348 records) |
| GX-017 | No retry for transient provider failures: bounded backoff + jitter + Retry-After, transient/permanent classification | adapter unit behavior in evaluator/orchestrator paths; `test_provider_429_benchmark_not_completed` |
| GX-018 | Blind redirect following: hop-by-hop re-validation, size cap | netguard unit tests |

## Verified NOT vulnerable

- SQL injection (parameterized ORM only — injection strings inert): `test_sql_injection_in_filters_is_inert`
- Secret redaction in events/audit (regression suite), tokens/hashes never returned after creation: `test_api_key_never_returned_again`
- Refusal of unregistered tools, approval-before-execution, deny-dominant conflicts (existing gateway suite, extended)
- Path traversal in sandbox executor (`test_gateway.py`)
- Oversized request bodies (413 guard): `test_oversized_request_body_rejected`

## Route-to-permission matrix (all routes authorization-tested)

| Route | Anonymous | Viewer | Researcher | Admin |
|---|---|---|---|---|
| GET /health, /ready, /setup/status | yes | yes | yes | yes |
| POST /auth/login, /auth/signup, /auth/reset-*, /auth/verify-email | yes (rate-limited) | — | — | — |
| POST /setup | only pre-first-admin + valid GX_SETUP_TOKEN | — | — | — |
| GET /auth/me, /auth/api-keys, logout, revoke-all, change-password | 401 | yes (own) | yes | yes |
| POST /auth/api-keys | 401 | 403 | yes (ceiling) | yes |
| GET /projects, /targets, /experiments, /findings, /benchmarks, /events | 401 | scoped | scoped | all |
| POST /projects | 401 | 403 | yes | yes |
| POST /targets, /experiments, /benchmarks/run | 401 | project-viewer→404 | project-researcher | yes |
| target test-connection / delete | 401 | 404 | project-researcher | yes |
| experiment start/cancel, finding verify | 401 | 404 | project-researcher | yes |
| POST /approvals/{id}/decide | 401 | 403 | 403 | yes |
| GET /admin/{stats,audit,users,events/severity}, POST /admin/* | 401 | 403 | 403 | yes |
| POST /admin/users/{id}/{role,disable,revoke-credentials} | 401 | 403 | 403 | yes |
| GET /dashboard/summary | 401 | scoped | scoped | all |
| /api/docs, /api/openapi.json | dev: yes; production: disabled | | | |

## Residual risks (documented, accepted for this release)

1. In-memory rate limiter and event bus are per-process (multi-worker needs shared store).
2. Account-token delivery supports SMTP; console delivery is development-only and hard-refused in production. No email API providers (SendGrid/SES) implemented yet.
3. Demo-data cleanup backups are plain files on disk; encrypt at rest per deployment policy.
4. `GX_ALLOW_LOCAL_ENDPOINTS=true` intentionally permits loopback egress for local model servers — enable only on trusted hosts.
