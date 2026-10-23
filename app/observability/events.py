"""Durable event recording with redaction, correlation IDs, and SSE fan-out."""
from __future__ import annotations

import threading
from typing import Any

from app.models import EventRecord, new_id
from app.observability.redaction import redact_obj

_seq_lock = threading.Lock()
_seq_counters: dict[str, int] = {}


def next_seq(experiment_id: str) -> int:
    with _seq_lock:
        _seq_counters[experiment_id] = _seq_counters.get(experiment_id, 0) + 1
        return _seq_counters[experiment_id]


def record_event(session, *, experiment_id: str | None, case_id: str | None = None,
                 trace_id: str | None = None, type_: str, actor: str = "system",
                 level: str = "info", payload: dict[str, Any] | None = None,
                 publish: bool = True) -> EventRecord:
    """Persist one event (redacted) and optionally fan out to SSE subscribers."""
    from app.observability.bus import bus
    ev = EventRecord(
        id=new_id("evt"), experiment_id=experiment_id, case_id=case_id, trace_id=trace_id,
        seq=next_seq(experiment_id or "global"), type=type_, actor=actor, level=level,
        payload=redact_obj(payload or {}),
    )
    session.add(ev)
    session.flush()
    if publish:
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(bus.publish(experiment_id, event_to_dict(ev)))
            else:
                loop.run_until_complete(bus.publish(experiment_id, event_to_dict(ev)))
        except RuntimeError:
            pass  # no running loop (tests) - durable record is enough
    return ev


def event_to_dict(ev: EventRecord) -> dict[str, Any]:
    return {
        "id": ev.id, "experiment_id": ev.experiment_id, "case_id": ev.case_id,
        "trace_id": ev.trace_id, "seq": ev.seq, "type": ev.type, "actor": ev.actor,
        "level": ev.level, "payload": ev.payload, "created_at": str(ev.created_at),
    }
