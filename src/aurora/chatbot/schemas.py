from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

INTENTS = (
    "AURORA_USAGE",
    "AURORA_NAVIGATION",
    "AURORA_DASHBOARD",
    "AURORA_CAMPAIGN",
    "AURORA_GOLDEN",
    "AURORA_REVIEW",
    "AURORA_SOURCE",
    "AURORA_REPORT",
    "AURORA_SECURITY_GUIDANCE",
    "AURORA_ACCESS_GUIDANCE",
    "OUT_OF_SCOPE",
    "SUSPICIOUS",
)


@dataclass(frozen=True)
class AssistantAction:
    action_id: str
    label: str
    route: str | None = None


@dataclass(frozen=True)
class AssistantSource:
    id: str
    publisher: str
    title: str
    reference: str | None = None
    version: str | None = None
    url: str | None = None


@dataclass(frozen=True)
class AssistantBrief:
    title: str
    generated_at: str
    scope: str
    executive_summary: str
    metrics: dict[str, int | float | str | None] = field(default_factory=dict)
    findings: tuple[str, ...] = ()
    recommendations: tuple[str, ...] = ()
    sources: tuple[AssistantSource, ...] = ()
    sections: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AssistantResponse:
    answer: str
    intent: str
    actions: tuple[AssistantAction, ...] = ()
    sources: tuple[AssistantSource, ...] = ()
    optional_document: AssistantBrief | None = None
    security_state: str = "ok"

    def as_dict(self) -> dict[str, Any]:
        return {
            "answer": self.answer,
            "intent": self.intent,
            "actions": [
                {
                    "action_id": a.action_id,
                    "label": a.label,
                    **({"route": a.route} if a.route else {}),
                }
                for a in self.actions
            ],
            "sources": [source.__dict__ for source in self.sources],
            "optional_document": (
                {
                    **self.optional_document.__dict__,
                    "sources": [source.__dict__ for source in self.optional_document.sources],
                }
                if self.optional_document
                else None
            ),
            "security_state": self.security_state,
        }
