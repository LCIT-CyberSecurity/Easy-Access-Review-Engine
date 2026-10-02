from __future__ import annotations

import unicodedata

from access_review_engine.chatbot.config import ChatbotConfig
from access_review_engine.chatbot.scope import classify
from access_review_engine.chatbot.security.secrets import redact_secrets


def guard_input(question: str, config: ChatbotConfig, route: str = "/") -> tuple[str, str, bool]:
    if not isinstance(question, str):
        raise ValueError("Message must be text")
    normalized = unicodedata.normalize("NFC", question).strip()
    if not normalized:
        raise ValueError("Message cannot be empty")
    if len(normalized) > config.max_message_chars:
        raise ValueError("Message is too long")
    safe, redacted = redact_secrets(normalized)
    return safe, classify(safe, route), redacted
