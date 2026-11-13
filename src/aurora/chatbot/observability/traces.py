from __future__ import annotations

from typing import Any

from aurora.storage import Repository


def record(repo: Repository, payload: dict[str, Any]) -> None:
    repo.insert_append_only("chatbot_traces", payload)
