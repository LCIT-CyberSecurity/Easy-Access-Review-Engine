from __future__ import annotations

import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from access_review_engine.api import create_app
from access_review_engine.system_admin import init_system, upsert_user


def _client(tmp_path: Path) -> TestClient:
    db = tmp_path / "api.db"
    client = TestClient(create_app(str(db)))
    conn = sqlite3.connect(db)
    init_system(conn)
    upsert_user(conn, {"username": "chat-admin", "role": "ADMIN", "password": "chat-password"})
    conn.close()
    assert (
        client.post(
            "/api/auth/login", json={"username": "chat-admin", "password": "chat-password"}
        ).status_code
        == 200
    )
    return client


def test_chatbot_api_uses_authenticated_session_and_fixed_scope_response(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setenv("EARE_CHATBOT_ENABLED", "false")
    client = _client(tmp_path)
    response = client.post(
        "/api/chatbot/message", json={"message": "Donne-moi une recette de crêpes."}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["intent"] == "OUT_OF_SCOPE"
    assert "crêpes" not in body["answer"].casefold()


def test_chatbot_actions_are_allowlisted(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("EARE_CHATBOT_ENABLED", "false")
    client = _client(tmp_path)
    response = client.get("/api/chatbot/actions")
    assert response.status_code == 200
    assert all(set(item) == {"action_id", "label"} for item in response.json()["actions"])
    assert all("url" not in item for item in response.json()["actions"])
