from __future__ import annotations

from typing import Any

from access_review_engine.chatbot.context import AuthorizationContext


def project_text(value: Any, limit: int = 300) -> str:
    text = str(value or "")
    return text[:limit]


def safe_metric(name: str, value: int | float | None) -> dict[str, int | float | None]:
    return {name: value}


def authorized_provider_rows(
    rows: list[dict[str, Any]], context: AuthorizationContext
) -> list[dict[str, Any]]:
    return [
        row
        for row in rows
        if context.can_access_provider(str(row.get("provider") or row.get("name") or ""))
    ]
