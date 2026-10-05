from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class ProviderCapabilities:
    supports_tools: bool
    supports_structured_output: bool
    supports_streaming: bool


@dataclass(frozen=True)
class ToolCall:
    call_id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class ProviderResult:
    text: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    usage: dict[str, int] = field(default_factory=dict)
    output_items: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True)
class ProviderHealth:
    ok: bool
    category: str


class LLMProvider(Protocol):
    capabilities: ProviderCapabilities

    def classify(self, question: str, route: str) -> str: ...
    def generate(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> ProviderResult: ...
    def validate_configuration(self) -> None: ...
    def healthcheck(self) -> ProviderHealth: ...
