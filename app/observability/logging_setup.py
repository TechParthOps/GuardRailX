"""Structured JSON logging with automatic secret redaction."""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone

from app.observability.redaction import redact_obj


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        for attr in ("event_type", "actor", "object_id"):
            v = getattr(record, attr, None)
            if v is not None:
                payload[attr] = v
        return json.dumps(redact_obj(payload), default=str)


def setup_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    root.setLevel(level.upper())
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    # Uvicorn loggers should also emit structured records
    for name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        lg = logging.getLogger(name)
        lg.handlers = []
        lg.propagate = True
