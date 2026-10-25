---
name: Bug report
about: Report broken behavior (not security vulnerabilities — use SECURITY.md)
labels: bug
---

## Summary
<!-- one or two sentences -->

## Environment
- OS:
- Python version:
- Database (SQLite/PostgreSQL):
- Deployment (local / Docker / compose):

## Steps to reproduce
<!-- minimal, deterministic steps; use synthetic data -->

## Expected behavior

## Actual behavior
<!-- include the relevant (redacted) logs -->

## Regression check
- [ ] `python -m pytest tests -q --ignore=tests/test_browser_workflows.py` passes on the current main
