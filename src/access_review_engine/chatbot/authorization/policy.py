from __future__ import annotations

from access_review_engine.chatbot.context import AuthorizationContext


def can_read_provider(context: AuthorizationContext, provider: str) -> bool:
    return context.can_access_provider(provider)


def visible_campaign(context: AuthorizationContext, campaign_providers: set[str]) -> bool:
    return context.role == "ADMIN" or (
        context.role == "OPERATOR"
        and ("*" in context.scopes or campaign_providers <= context.scopes)
    )
