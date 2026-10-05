from __future__ import annotations

import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from access_review_engine.api import create_app
from access_review_engine.system_admin import init_system, set_chatbot_enabled, upsert_user


def _client(tmp_path: Path) -> TestClient:
    db = tmp_path / "api.db"
    client = TestClient(create_app(str(db)))
    conn = sqlite3.connect(db)
    init_system(conn)
    upsert_user(
        conn,
        {
            "username": "chat-admin", "role": "ADMIN", "password": "chat-password",
            "chatbot_access_enabled": True,
        },
    )
    set_chatbot_enabled(conn, True)
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
    monkeypatch.setenv("EARE_CHATBOT_ENABLED", "true")
    monkeypatch.setenv("EARE_OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("EARE_OPENAI_MODEL", "test-model")
    client = _client(tmp_path)
    response = client.post(
        "/api/chatbot/message", json={"message": "Donne-moi une recette de crêpes."}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["intent"] == "OUT_OF_SCOPE"
    assert "crêpes" not in body["answer"].casefold()


def test_chatbot_actions_are_allowlisted(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("EARE_CHATBOT_ENABLED", "true")
    monkeypatch.setenv("EARE_OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("EARE_OPENAI_MODEL", "test-model")
    client = _client(tmp_path)
    response = client.get("/api/chatbot/actions")
    assert response.status_code == 200
    assert all(set(item) == {"action_id", "label"} for item in response.json()["actions"])
    assert all("url" not in item for item in response.json()["actions"])


def test_chatbot_brief_and_markdown_report_are_controlled(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("EARE_CHATBOT_ENABLED", "true")
    monkeypatch.setenv("EARE_OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("EARE_OPENAI_MODEL", "test-model")
    client = _client(tmp_path)
    brief = client.get("/api/chatbot/brief?route=/")
    assert brief.status_code == 200
    assert {
        "title", "generated_at", "scope", "executive_summary", "metrics", "findings",
        "recommendations",
    } <= set(brief.json())
    report = client.get("/api/chatbot/report?route=/")
    assert report.status_code == 200
    assert report.headers["content-type"].startswith("text/markdown")
    assert "# Synthèse EARE" in report.text


def test_chatbot_actions_follow_the_shared_role_contract(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("EARE_CHATBOT_ENABLED", "true")
    monkeypatch.setenv("EARE_OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("EARE_OPENAI_MODEL", "test-model")
    client = _client(tmp_path)
    conn = sqlite3.connect(tmp_path / "api.db")
    init_system(conn)
    for role in ("OPERATOR", "GROUP_OWNER", "BUSINESS_ADMIN", "REMEDIATION_MANAGER"):
        upsert_user(conn, {
            "username": f"{role.lower()}-user", "role": role, "password": "role-password",
            "scopes": ["A"], "chatbot_access_enabled": True,
        })
    conn.close()
    expected = {
        "OPERATOR": {
            "OPEN_GOLDEN", "OPEN_CAMPAIGN", "OPEN_PENDING_REVIEWS",
            "OPEN_ACTIONS", "OPEN_SOURCES", "OPEN_REPORTS", "OPEN_PERIMETERS",
            "OPEN_IDENTITIES", "OPEN_ACCESSES", "CREATE_CAMPAIGN",
        },
        "GROUP_OWNER": {"OPEN_PENDING_REVIEWS"},
        "BUSINESS_ADMIN": {"OPEN_ACTIONS"},
        "REMEDIATION_MANAGER": {"OPEN_ACTIONS"},
    }
    for role, action_ids in expected.items():
        login = client.post(
            "/api/auth/login",
            json={"username": f"{role.lower()}-user", "password": "role-password"},
        )
        assert login.status_code == 200
        response = client.get("/api/chatbot/actions")
        assert {item["action_id"] for item in response.json()["actions"]} == action_ids
