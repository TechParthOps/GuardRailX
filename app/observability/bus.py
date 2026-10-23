"""In-process pub/sub event bus used for SSE live updates.

The database remains the durable event store; this bus only fans out
to connected dashboard clients.
"""
from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any


class EventBus:
    def __init__(self) -> None:
        self._subs: dict[str, set[asyncio.Queue]] = defaultdict(set)
        self._global_subs: set[asyncio.Queue] = set()
        self._lock = asyncio.Lock()

    async def subscribe(self, experiment_id: str | None = None) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        async with self._lock:
            if experiment_id:
                self._subs[experiment_id].add(q)
            else:
                self._global_subs.add(q)
        return q

    async def unsubscribe(self, q: asyncio.Queue, experiment_id: str | None = None) -> None:
        async with self._lock:
            if experiment_id:
                self._subs[experiment_id].discard(q)
                if not self._subs[experiment_id]:
                    self._subs.pop(experiment_id, None)
            else:
                self._global_subs.discard(q)

    async def publish(self, experiment_id: str | None, event: dict[str, Any]) -> None:
        targets = list(self._global_subs)
        if experiment_id:
            targets.extend(self._subs.get(experiment_id, ()))
        for q in targets:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass  # slow consumer; durable events remain in DB


bus = EventBus()
