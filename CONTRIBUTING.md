# Contributing to GuardrailX

Thanks for considering a contribution. GuardrailX is a security-sensitive
tool: changes are reviewed with that lens.

## Ground rules

1. **Authorized testing only.** Contributions must not add capabilities for
   testing systems without authorization, bypassing third-party safety
   controls wholesale, or extracting real credentials. See `SECURITY.md` and
   `docs/SECURITY_LIMITATIONS.md`.
2. **Preserve security boundaries.** The enforcement gateway
   (`app/tools/gateway.py`) is fail-closed by design; the policy engine's
   deny-dominance, the API-key privilege ceiling, project isolation, and the
   pinned outbound transport must not be weakened.
3. **No fabricated results.** Tests, benchmarks, and reports must reflect
   actual execution.

## Development setup

```bash
git clone <your fork>
cd guardrailx
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
python -m app.setup        # create a local admin for manual testing (optional)
python -m pytest tests -q --ignore=tests/test_browser_workflows.py
```

The offline suite requires no real API credentials (fake values are injected
by test fixtures) and must never make external network calls.

## Before opening a PR

- [ ] `python -m pytest tests -q --ignore=tests/test_browser_workflows.py` passes.
- [ ] New behavior has regression tests.
- [ ] Security-sensitive changes include an explicit test of the boundary.
- [ ] No secrets, local databases, or runtime artifacts are committed
      (`git ls-files` should stay clean of the patterns in `.gitignore`).
- [ ] Documentation updated where behavior changed (`docs/`, `README.md`,
      `.env.example`).
- [ ] `python scripts/make_release.py` still passes (packaging rules).

## Code style

- Type hints on new code; Pydantic models for API inputs (`extra="forbid"`).
- Async endpoints where I/O-bound; sync where CPU/DB-bound.
- Events and audit records go through the redaction helpers in
  `app/observability/redaction.py` — never log credentials or tokens.

## Reporting security issues

See `SECURITY.md` — please do not open public issues for vulnerabilities.
