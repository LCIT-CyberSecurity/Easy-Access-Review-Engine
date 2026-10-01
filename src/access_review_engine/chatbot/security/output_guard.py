from __future__ import annotations

import re

from access_review_engine.chatbot.schemas import AssistantAction

_DANGEROUS = re.compile(r"(?:javascript|data|file):|<\s*(?:script|iframe|object|img)\b", re.I)
_SECRET = re.compile(r"(?:bearer\s+|-----BEGIN|api[_ -]?key\s*[:=])", re.I)


def validate_answer(answer: str, max_chars: int) -> str:
    if not isinstance(answer, str) or len(answer) > max_chars or _DANGEROUS.search(answer):
        raise ValueError("Unsafe assistant output")
    if _SECRET.search(answer):
        raise ValueError("Sensitive assistant output")
    return answer


def validate_action(action_id: str, label: str, allowed: set[str]) -> AssistantAction:
    if action_id not in allowed or _DANGEROUS.search(label):
        raise ValueError("Unknown or unsafe assistant action")
    return AssistantAction(action_id, label[:120])
