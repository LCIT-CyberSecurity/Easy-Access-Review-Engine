from __future__ import annotations

from typing import Any

from aurora.services import audit
from aurora.storage import Repository


def record(repo: Repository, event: str, user: str, details: dict[str, Any] | None = None) -> None:
    item = audit(event, "chatbot", user)
    item.actor = user
    item.details = details or {}
    repo.insert_append_only("audit_events", item)
