from __future__ import annotations

from typing import Any

from access_review_engine.chatbot.context import AuthorizationContext, UIHints
from access_review_engine.chatbot.ui_catalog import find_ui_page
from access_review_engine.storage import Repository


def get_ui_help(
    repo: Repository, args: dict[str, Any], context: AuthorizationContext, hints: UIHints
) -> dict[str, Any]:
    del repo
    requested_topic = str(args.get("topic") or "")
    requested_page = str(args.get("page") or "")
    if not requested_topic and not requested_page:
        requested_page = hints.route
    page = find_ui_page(
        context.role,
        topic=requested_topic,
        page=requested_page,
    )
    if page is None:
        return {"available": False, "item": None}
    return {
        "available": True,
        "item": {
            "title": page.label,
            "purpose": page.purpose,
            "navigation_path": page.navigation_path,
            "semantic_action_id": page.semantic_id,
            "route": page.route,
        },
    }


UI_TOOL_FUNCTIONS = {"get_ui_help": get_ui_help}
UI_TOOL_SCHEMAS = [
    {
        "type": "function",
        "name": "get_ui_help",
        "description": "Resolve controlled EARE UI help and routes authorized for the current role",
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": {
                "topic": {"type": ["string", "null"], "maxLength": 200},
                "page": {"type": ["string", "null"], "maxLength": 200},
            },
            "required": [],
            "additionalProperties": False,
        },
    }
]
