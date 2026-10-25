## Description
<!-- what does this PR change and why? -->

## Type of change
- [ ] Bug fix (non-breaking)
- [ ] Security fix
- [ ] New feature
- [ ] Refactor (no behavior change)
- [ ] Documentation
- [ ] Tests only

## Security checklist
- [ ] No secrets, tokens, or local databases added
- [ ] New inputs validated (Pydantic, `extra="forbid"`)
- [ ] New outbound traffic passes the netguard/pinned transport
- [ ] New tool paths pass the enforcement gateway
- [ ] Events/audit records use redaction helpers
- [ ] Regression tests added for any fixed boundary

## Testing
- Commands run and results (exact counts):

```
python -m pytest tests -q --ignore=tests/test_browser_workflows.py
```

## Documentation
- [ ] README / docs / .env.example updated where behavior changed
