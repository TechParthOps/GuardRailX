"""Module A — Universal model/agent adapter contract.

Every adapter normalizes provider interaction behind this interface and
declares its capabilities. Adapters never read secrets from the database:
credentials are resolved from the environment at call time.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AdapterRequest:
    messages: list[dict[str, Any]]          # [{role, content, name?}]
    tools: list[dict[str, Any]] = field(default_factory=list)
    max_tokens: int = 1024
    temperature: float | None = None
    system: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ModelResponse:
    text: str
    proposed_tool_calls: list[dict[str, Any]] = field(default_factory=list)  # [{name, arguments}]
    stop_reason: str = "end_turn"
    raw_ref: str = ""                        # provider id or content hash (no secrets)
    latency_ms: int = 0
    usage: dict[str, Any] = field(default_factory=dict)
    error: str | None = None                 # set only for provider-side errors


class AdapterError(Exception):
    """Infrastructure-level failure (network, auth, protocol)."""


@dataclass
class HealthResult:
    ok: bool
    detail: str
    latency_ms: int = 0


class ModelAdapter(ABC):
    """Common contract for hosted APIs, local servers, and agent runners."""

    name: str = "abstract"
    version: str = "0.0.0"
    supported_models: list[str] = []
    auth_requirements: list[str] = []        # env var names, e.g. ["OPENAI_API_KEY"]
    modalities: list[str] = ["text"]         # text | image | audio | file
    supports_tool_calling: bool = False
    supports_streaming: bool = False
    supports_seeds: bool = False
    timeout_seconds: float = 60.0
    notes: str = ""                          # data-retention / processing limitations

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "supported_models": self.supported_models,
            "auth_requirements": self.auth_requirements,
            "modalities": self.modalities,
            "supports_tool_calling": self.supports_tool_calling,
            "supports_streaming": self.supports_streaming,
            "supports_seeds": self.supports_seeds,
            "timeout_seconds": self.timeout_seconds,
            "notes": self.notes,
        }

    @abstractmethod
    def validate_config(self, config: dict[str, Any]) -> tuple[bool, str]:
        """Validate non-secret target config. Fails closed."""

    @abstractmethod
    def health_check(self, config: dict[str, Any]) -> HealthResult:
        """Real connection test. Marks a target operational ONLY on success."""

    @abstractmethod
    def generate(self, request: AdapterRequest, config: dict[str, Any]) -> ModelResponse:
        """Execute one normalized model turn."""
