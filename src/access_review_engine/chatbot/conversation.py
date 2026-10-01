from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from access_review_engine.storage import Repository


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
