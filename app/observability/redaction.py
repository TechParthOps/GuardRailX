"""Secret redaction applied to logs, events, and evidence before persistence."""
from __future__ import annotations

import re
from typing import Any

# Ordered patterns; each replaced by a labeled placeholder.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("REDACTED_API_KEY", re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")),
    ("REDACTED_API_KEY", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{8,}\b")),
    ("REDACTED_BEARER", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b")),
    ("REDACTED_KEYVAL", re.compile(r"(?i)\b(api[_-]?key|authorization|password|token|secret)\b(\s*[:=]\s*)(\"[^\"]{4,}\"|'[^']{4,}'|(?![A-Z]+_)[^\s,;&\"']{4,})")),
    ("REDACTED_AWS", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("REDACTED_GITHUB", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("REDACTED_JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
]

SENSITIVE_FIELD_NAMES = {
    "password", "password_hash", "secret", "api_key", "authorization",
    "token", "access_token", "refresh_token", "secret_key", "credential",
    "credentials", "private_key",
}


def redact_text(text: str) -> str:
    if not isinstance(text, str):
        return text
    out = text
    for placeholder, pattern in _PATTERNS:
        out = pattern.sub(placeholder, out)
    return out


def redact_obj(value: Any, _key: str | None = None, depth: int = 0) -> Any:
    """Recursively redact strings and mask sensitive-named fields."""
    if depth > 12:
        return "[depth-limit]"
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(k, str) and k.lower() in SENSITIVE_FIELD_NAMES and v:
                out[k] = "[REDACTED]"
            else:
                out[k] = redact_obj(v, _key=k, depth=depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [redact_obj(v, _key=_key, depth=depth + 1) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
