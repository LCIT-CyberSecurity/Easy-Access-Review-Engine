from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class ChatbotConfig:
    enabled: bool = False
    provider: str = "openai"
    api_key: str | None = None
    model: str | None = None
    timeout_seconds: float = 20.0
    max_output_tokens: int = 800
    max_tool_rounds: int = 3
    max_tool_calls: int = 6
    max_message_chars: int = 8000
    max_history_messages: int = 12
    max_context_chars: int = 24000
    max_result_items: int = 100
    store_message_content: bool = True
    log_conversations: bool = True
    log_tool_calls: bool = True
    trace_retention_days: int = 30

    @classmethod
    def from_env(cls) -> ChatbotConfig:
        def integer(name: str, default: int, minimum: int, maximum: int) -> int:
            try:
                return max(minimum, min(maximum, int(os.environ.get(name, default))))
            except ValueError:
                return default

        try:
            timeout = max(1.0, min(60.0, float(os.environ.get("EARE_CHATBOT_TIMEOUT", "20"))))
        except ValueError:
            timeout = 20.0
        return cls(
            enabled=os.environ.get("EARE_CHATBOT_ENABLED", "false").casefold() == "true",
            provider=os.environ.get("EARE_CHATBOT_PROVIDER", "openai").strip().casefold(),
            api_key=os.environ.get("EARE_OPENAI_API_KEY") or None,
            model=os.environ.get("EARE_OPENAI_MODEL") or None,
            timeout_seconds=timeout,
            max_output_tokens=integer("EARE_CHATBOT_MAX_OUTPUT_TOKENS", 800, 64, 4000),
            max_tool_rounds=integer("EARE_CHATBOT_MAX_TOOL_ROUNDS", 3, 1, 5),
            max_tool_calls=integer("EARE_CHATBOT_MAX_TOOL_CALLS", 6, 1, 20),
            max_message_chars=integer("EARE_CHATBOT_MAX_MESSAGE_CHARS", 8000, 100, 20000),
            max_history_messages=integer("EARE_CHATBOT_MAX_HISTORY_MESSAGES", 12, 2, 30),
            max_context_chars=integer("EARE_CHATBOT_MAX_CONTEXT_CHARS", 24000, 4000, 100000),
            max_result_items=integer("EARE_CHATBOT_MAX_RESULT_ITEMS", 100, 1, 500),
            store_message_content=(
                os.environ.get("EARE_CHATBOT_STORE_MESSAGE_CONTENT", "true").casefold() == "true"
            ),
            log_conversations=(
                os.environ.get("EARE_CHATBOT_LOG_CONVERSATIONS", "true").casefold() == "true"
            ),
            log_tool_calls=(
                os.environ.get("EARE_CHATBOT_LOG_TOOL_CALLS", "true").casefold() == "true"
            ),
            trace_retention_days=integer("EARE_CHATBOT_TRACE_RETENTION_DAYS", 30, 1, 3650),
        )
