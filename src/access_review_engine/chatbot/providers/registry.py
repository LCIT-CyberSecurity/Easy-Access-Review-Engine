from __future__ import annotations

from access_review_engine.chatbot.config import ChatbotConfig
from access_review_engine.chatbot.providers.base import LLMProvider
from access_review_engine.chatbot.providers.openai import OpenAIProvider, ProviderError


def build_provider(config: ChatbotConfig) -> LLMProvider:
    if config.provider == "openai":
        return OpenAIProvider(config)
    raise ProviderError(f"Unsupported chatbot provider: {config.provider}")
