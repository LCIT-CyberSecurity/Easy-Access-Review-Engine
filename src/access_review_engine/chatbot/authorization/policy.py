from __future__ import annotations

from access_review_engine.campaign_authorization import can_access_campaign
from access_review_engine.chatbot.context import AuthorizationContext


def can_read_provider(context: AuthorizationContext, provider: str) -> bool:
    return context.can_access_provider(provider)


def visible_campaign(context: AuthorizationContext, campaign_providers: set[str]) -> bool:
    if context.role == "ADMIN":
        return True
    if context.role != "OPERATOR":
        return False
    if not campaign_providers:
        return False
    return can_access_campaign(context.role, context.scopes, campaign_providers)
