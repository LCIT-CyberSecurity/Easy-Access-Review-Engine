from __future__ import annotations

from aurora.chatbot.config import ChatbotConfig
from aurora.chatbot.providers.base import LLMProvider
from aurora.chatbot.providers.openai import OpenAIProvider, ProviderError


def build_provider(config: ChatbotConfig) -> LLMProvider:
    if config.provider == "openai":
        return OpenAIProvider(config)
    raise ProviderError(
        f"Unsupported chatbot provider: {config.provider}", category="provider_error"
    )
