# Threat model

## Trust boundaries

```
+----------------------------------------------------------------------------------+
| CONTROL PLANE (trusted)                                                          |
|  Dashboard/API users ── auth ── RBAC ── policies ── approvals ── audit log       |
|        │                                                                          |
|        ▼                                                                          |
|  Orchestrator ── Adapter registry ── Provider APIs  (external, semi-trusted)     |
|        │                                                                          |
|        ▼                                                                          |
+----------------------------------------------------------------------------------+
         │ policy decision (PDP)          ▲ events only (redacted)
         ▼                                │
+----------------------------------------------------------------------------------+
| ENFORCEMENT PLANE                                                                 |
|  Gateway (PEP) ── sandboxed tool executor ── data/sandbox (only real fs access)  |
|         ▲                                                                         |
|         │ proposed tool calls (UNTRUSTED — may be attacker-influenced)           |
|  TARGET MODEL/AGENT (untrusted: prompts, outputs, tool proposals)                |
+----------------------------------------------------------------------------------+
```

## Assets

1. Provider API keys (env vars only; never stored, never logged).
2. Evaluation evidence integrity (audit trail, event store).
3. Host filesystem (only `data/sandbox/` is reachable, read-mostly).
4. Control plane (policy activation, approvals, emergency stop).

## Attack surfaces and mitigations

| Surface | Threat | Mitigation |
|---|---|---|
| Target model output | prompt-influenced tool proposals | gateway PDP on every call; deny by default; no shell tool |
| Target model output | secret exfiltration | canary leak detection; output redaction; approval-gated egress |
| Retrieved documents / imported scenarios | indirect injection into the platform itself | treated as untrusted strings; never interpreted as authorization; scenario templates validated (outcome/tool fields typed) |
| Sandbox executor | path traversal (`/etc/passwd`, `C:\...`, `..`) | absolute paths refused; `..` refused; `resolve().relative_to()` containment |
| Gateway | fail-open on crash | every exception → blocked result, never success |
| Approvals | self-approval by agent | approvals decided only by authenticated humans (admin role); pending actions never execute |
| Policies | conflicting rules | deny dominates; conflicts surfaced via `/policies/{id}/conflicts` |
| Dashboard/API | unauthenticated access, privilege escalation | bearer-only auth, PBKDF2 hashes, token hashes w/ server secret, role checks per endpoint, viewer cannot mint elevated keys |
| Logs/events | secret leakage | recursive redaction of key patterns + sensitive field names before persistence |
| Audit trail | tampering by compromised agent | agents have no API surface; writes occur only in control-plane code paths |
| Experiment scope | scope creep | authorization record required (acknowledged + authorized_by); emergency stop freezes new and running experiments |
| Platform deps | supply chain | minimal dependency set; requirements pinned with `>=` floors; compose builds from slim base |

## Out of scope / explicitly not protected

- Provider-side retention of prompts (documented in adapter `notes`; use local endpoints for sensitive evaluations).
- Non-instrumented side channels (provider-internal filtering is unobservable and labeled as such).
- Multi-node deployments (in-memory rate limiter and event bus are per-process).
