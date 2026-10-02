from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from access_review_engine.chatbot.config import ChatbotConfig


def provider_configured(config: ChatbotConfig) -> bool:
    """Return local readiness only; never performs a provider/network healthcheck."""
    return (
        config.provider == "openai"
        and bool(config.api_key)
        and bool(config.model)
    )


def chatbot_access_status(
    config: ChatbotConfig,
    global_enabled: bool,
    user: Mapping[str, Any] | None,
) -> dict[str, bool]:
    """Compute effective chatbot availability from deployment and admin state."""
    deployment_enabled = bool(config.enabled)
    user_enabled = bool(user and user.get("enabled") and user.get("chatbot_access_enabled"))
    configured = provider_configured(config)
    return {
        "available": deployment_enabled and bool(global_enabled) and user_enabled and configured,
        "deployment_enabled": deployment_enabled,
        "global_enabled": bool(global_enabled),
        "user_enabled": user_enabled,
        "configured": configured,
    }


def can_use_chatbot(
    config: ChatbotConfig,
    global_enabled: bool,
    user: Mapping[str, Any] | None,
) -> bool:
    return chatbot_access_status(config, global_enabled, user)["available"]
