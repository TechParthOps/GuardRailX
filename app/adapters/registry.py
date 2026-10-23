"""Adapter registry: discovery, config validation, health checks, compatibility tests."""
from __future__ import annotations

import logging
from typing import Any

from app.adapters.base import AdapterError, HealthResult, ModelAdapter
from app.adapters.mock import MockAdapter
from app.adapters.anthropic import AnthropicAdapter
from app.adapters.openai_compatible import OpenAICompatibleAdapter

log = logging.getLogger("guardrailx.adapters")


class AdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, ModelAdapter] = {}
        self.register(MockAdapter())
        self.register(OpenAICompatibleAdapter())
        self.register(AnthropicAdapter())

    def register(self, adapter: ModelAdapter) -> None:
        if adapter.name in self._adapters:
            raise ValueError(f"adapter '{adapter.name}' already registered")
        self._adapters[adapter.name] = adapter

    def get(self, name: str) -> ModelAdapter:
        try:
            return self._adapters[name]
        except KeyError:
            raise KeyError(f"unknown adapter '{name}'. registered: {sorted(self._adapters)}") from None

    def list(self) -> list[dict[str, Any]]:
        return [a.describe() for a in self._adapters.values()]

    def missing_credentials(self, name: str) -> list[str]:
        """Which required env vars are absent (informational; health check is authoritative)."""
        import os
        adapter = self.get(name)
        return [e for e in adapter.auth_requirements if not os.environ.get(e)]

    def test_connection(self, name: str, config: dict[str, Any]) -> HealthResult:
        """Run a REAL connection test. Fail-closed on any error."""
        adapter = self.get(name)
        try:
            result = adapter.health_check(config)
        except Exception as exc:  # defensive: never mark operational on unexpected errors
            log.warning("health check crashed", exc_info=True)
            result = HealthResult(ok=False, detail=f"health check error: {type(exc).__name__}")
        return result


registry = AdapterRegistry()
