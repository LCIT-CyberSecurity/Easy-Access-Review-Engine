from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from access_review_engine.storage import Repository

_last_cleanup_at: dict[str, float] = {}


def _now() -> str:
    return datetime.now(UTC).isoformat()


class ConversationStore:
    def __init__(self, repo: Repository, user_id: str) -> None:
        self.repo = repo
        self.user_id = user_id

    def get_or_create(self, conversation_id: str | None) -> str:
        if conversation_id:
            row = self.repo.get_payload("chatbot_conversations", conversation_id)
            if row and row.get("user_id") == self.user_id:
                return conversation_id
            raise PermissionError("Conversation is not available in your scope")
        identifier = str(uuid.uuid4())
        self.repo.upsert(
            "chatbot_conversations",
            {"id": identifier, "user_id": self.user_id, "created_at": _now(), "updated_at": _now()},
        )
        return identifier

    def append(self, conversation_id: str, role: str, content: str) -> str:
        message_id = str(uuid.uuid4())
        self.repo.insert_append_only(
            "chatbot_messages",
            {
                "id": message_id,
                "conversation_id": conversation_id,
                "user_id": self.user_id,
                "role": role,
                "content": content,
                "created_at": _now(),
            },
        )
        row = self.repo.get_payload("chatbot_conversations", conversation_id) or {}
        row["updated_at"] = _now()
        self.repo.upsert("chatbot_conversations", row)
        return message_id

    def history(self, conversation_id: str, limit: int) -> list[dict[str, Any]]:
        return [
            row
            for row in self.repo.list_payloads("chatbot_messages")
            if row.get("conversation_id") == conversation_id and row.get("user_id") == self.user_id
        ][-limit:]


def cleanup_expired_chatbot_data(repo: Repository, retention_days: int) -> int:
    """Delete expired chatbot messages/traces and orphaned conversations only."""
    cutoff = (datetime.now(UTC) - timedelta(days=max(1, retention_days))).isoformat()
    removed = 0
    for table in ("chatbot_messages", "chatbot_traces"):
        rows = repo.list_payloads(table)
        ids = {str(row.get("id")) for row in rows if str(row.get("created_at") or "") < cutoff}
        repo.delete_ids(table, ids)
        removed += len(ids)
    conversation_ids = {
        str(row.get("conversation_id")) for row in repo.list_payloads("chatbot_messages")
    }
    orphan_ids = {
        str(row.get("id"))
        for row in repo.list_payloads("chatbot_conversations")
        if str(row.get("id")) not in conversation_ids
        and str(row.get("updated_at") or row.get("created_at") or "") < cutoff
    }
    repo.delete_ids("chatbot_conversations", orphan_ids)
    return removed + len(orphan_ids)


def cleanup_expired_chatbot_data_periodically(repo: Repository, retention_days: int) -> None:
    """Bound cleanup to one pass per repository path and five-minute interval."""
    import time

    now = time.monotonic()
    key = repo.path
    if now - _last_cleanup_at.get(key, 0.0) >= 300:
        cleanup_expired_chatbot_data(repo, retention_days)
        _last_cleanup_at[key] = now
