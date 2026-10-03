from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

INTENTS = (
    "EARE_USAGE",
    "EARE_NAVIGATION",
    "EARE_DASHBOARD",
    "EARE_CAMPAIGN",
    "EARE_GOLDEN",
    "EARE_REVIEW",
    "EARE_SOURCE",
    "EARE_REPORT",
    "EARE_SECURITY_GUIDANCE",
    "EARE_ACCESS_GUIDANCE",
    "OUT_OF_SCOPE",
    "SUSPICIOUS",
)


@dataclass(frozen=True)
class AssistantAction:
    action_id: str
    label: str
    route: str | None = None


@dataclass(frozen=True)
class AssistantBrief:
    title: str
    generated_at: str
    scope: str
    executive_summary: str
    metrics: dict[str, int | float | str | None] = field(default_factory=dict)
    findings: tuple[str, ...] = ()
    recommendations: tuple[str, ...] = ()


@dataclass(frozen=True)
class AssistantResponse:
    answer: str
    intent: str
    actions: tuple[AssistantAction, ...] = ()
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
            "optional_document": self.optional_document.__dict__
            if self.optional_document
            else None,
            "security_state": self.security_state,
        }
