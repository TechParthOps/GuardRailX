# Security Policy

## Supported versions

Only the latest tagged release receives security fixes.

## Reporting a vulnerability

**Do not open a public GitHub issue for security problems.**

Use GitHub's private vulnerability reporting (Repository → Security →
"Report a vulnerability") or contact the maintainers directly (see the
repository owner profile). Include:

- Affected component and file path
- Reproduction steps in an authorized test environment
- Impact assessment

You will receive an acknowledgement within 7 days. Please allow up to 90
days for a fix before public disclosure.

## Scope notes

GuardrailX is an authorized-testing platform. Reports about *bypassing the
tool's own guardrails against unauthorized third parties* are in scope;
requests to add capabilities for attacking systems without authorization are
not.

## Security controls worth knowing before you report

- Independent policy enforcement gateway (fail-closed)
- API-key privilege ceilings + project-level isolation
- Outbound endpoint allowlisting with connection-time IP pinning
- Argon2id password hashing, hashed tokens, atomic single-use account tokens
- Secret redaction on events, audit records, and logs

Current limitations are documented honestly in
`docs/SECURITY_LIMITATIONS.md` — please read it before testing or reporting.
