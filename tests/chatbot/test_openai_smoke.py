"""Opt-in OpenAI transport smoke test; never required for CI."""
from __future__ import annotations

import os

import pytest
from access_review_engine.chatbot.config import ChatbotConfig
from access_review_engine.chatbot.providers.openai import OpenAIProvider


@pytest.mark.skipif(
    os.environ.get("EARE_CHATBOT_LIVE_SMOKE") != "true",
    reason="live provider smoke test is opt-in",
)
def test_openai_provider_live_smoke_does_not_store_responses() -> None:
    config = ChatbotConfig.from_env()
    provider = OpenAIProvider(config)
    result = provider.generate(
        [{"role": "user", "content": "Explain in one sentence what EARE is."}], []
    )
    assert result.text
    assert len(result.text) <= config.max_message_chars
