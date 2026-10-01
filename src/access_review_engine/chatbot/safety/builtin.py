from __future__ import annotations

from access_review_engine.chatbot.config import ChatbotConfig
from access_review_engine.chatbot.security.input_guard import guard_input
from access_review_engine.chatbot.security.output_guard import validate_answer


class BuiltInSafetyProvider:
    def __init__(self, config: ChatbotConfig) -> None:
        self.config = config

    def check_input(self, question: str) -> tuple[str, str, bool]:
        return guard_input(question, self.config)

    def check_output(self, answer: str) -> str:
        return validate_answer(answer, self.config.max_message_chars)
