from __future__ import annotations

import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from access_review_engine.api import create_app
from access_review_engine.chatbot.access import chatbot_access_status
from access_review_engine.chatbot.config import ChatbotConfig
from access_review_engine.storage import Repository
from access_review_engine.system_admin import (
    chatbot_enabled,
    init_system,
    list_users,
    set_chatbot_enabled,
    upsert_user,
)


def test_chatbot_defaults_and_user_flag_preservation(tmp_path: Path):
    conn = sqlite3.connect(tmp_path / "system.db")
    conn.row_factory = sqlite3.Row
    init_system(conn)
    assert chatbot_enabled(conn) is False
    upsert_user(conn, {"username": "alice", "role": "OPERATOR", "password": "password-12345"})
    alice = next(user for user in list_users(conn) if user["username"] == "alice")
    assert alice["chatbot_access_enabled"] is False
    upsert_user(
        conn,
        {
            "username": "alice",
            "role": "OPERATOR",
            "password": "password-12345",
            "chatbot_access_enabled": True,
        },
    )
    upsert_user(conn, {"username": "alice", "role": "OPERATOR"})
    alice = next(user for user in list_users(conn) if user["username"] == "alice")
    assert alice["chatbot_access_enabled"] is True


def test_effective_access_matrix(monkeypatch):
    monkeypatch.setenv("EARE_CHATBOT_PROVIDER", "openai")
    monkeypatch.setenv("EARE_OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("EARE_OPENAI_MODEL", "test-model")
    config = ChatbotConfig.from_env()
    user = {"enabled": True, "chatbot_access_enabled": True}
    assert chatbot_access_status(config, True, user)["available"] is False
    monkeypatch.setenv("EARE_CHATBOT_ENABLED", "true")
    config = ChatbotConfig.from_env()
    assert chatbot_access_status(config, False, user)["available"] is False
    assert chatbot_access_status(
        config, True, {**user, "chatbot_access_enabled": False}
    )["available"] is False
    monkeypatch.delenv("EARE_OPENAI_API_KEY")
    assert chatbot_access_status(ChatbotConfig.from_env(), True, user)["available"] is False
    monkeypatch.setenv("EARE_OPENAI_API_KEY", "test-key")
    assert chatbot_access_status(ChatbotConfig.from_env(), True, user)["available"] is True


def _admin_client(tmp_path: Path, monkeypatch) -> tuple[TestClient, Path]:
    monkeypatch.setenv("EARE_CHATBOT_ENABLED", "true")
    monkeypatch.setenv("EARE_OPENAI_PROVIDER", "openai")
    monkeypatch.setenv("EARE_OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("EARE_OPENAI_MODEL", "test-model")
    db = tmp_path / "api.db"
    client = TestClient(create_app(str(db)))
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    init_system(conn)
    upsert_user(
        conn,
        {
            "username": "admin",
            "role": "ADMIN",
            "password": "admin-password",
            "chatbot_access_enabled": True,
            "must_change_password": False,
        },
    )
    upsert_user(
        conn,
        {
            "username": "alice",
            "role": "OPERATOR",
            "scopes": ["provider-a"],
            "password": "alice-password",
            "chatbot_access_enabled": False,
        },
    )
    set_chatbot_enabled(conn, True)
    conn.close()
    return client, db


def test_server_enforcement_and_live_user_revocation(tmp_path: Path, monkeypatch):
    client, db = _admin_client(tmp_path, monkeypatch)
    assert client.post(
        "/api/auth/login", json={"username": "alice", "password": "alice-password"}
    ).status_code == 200
    assert client.get("/api/chatbot/status").json()["available"] is False
    for method, path in (
        ("post", "/api/chatbot/message"),
        ("get", "/api/chatbot/actions"),
        ("get", "/api/chatbot/brief"),
        ("get", "/api/chatbot/report"),
    ):
        response = (
            client.post(path, json={"message": "Résumé EARE"})
            if method == "post"
            else client.get(path)
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "Chatbot access is disabled."

    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    upsert_user(
        conn,
        {
            "username": "alice", "role": "OPERATOR", "scopes": ["provider-a"],
            "chatbot_access_enabled": True,
        },
    )
    conn.close()
    assert client.get("/api/chatbot/status").json()["available"] is True
    assert client.post(
        "/api/chatbot/message", json={"message": "Quelle est la capitale du Japon ?"}
    ).status_code == 200

    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    upsert_user(
        conn,
        {
            "username": "alice", "role": "OPERATOR", "scopes": ["provider-a"],
            "chatbot_access_enabled": False,
        },
    )
    conn.close()
    assert client.get("/api/chatbot/status").json()["available"] is False
    assert client.post("/api/chatbot/message", json={"message": "Résumé EARE"}).status_code == 403


def test_admin_global_toggle_audit_and_non_admin_denied(tmp_path: Path, monkeypatch):
    client, db = _admin_client(tmp_path, monkeypatch)
    assert client.post(
        "/api/auth/login", json={"username": "alice", "password": "alice-password"}
    ).status_code == 200
    assert client.put("/api/system/settings/chatbot", json={"enabled": True}).status_code == 403
    assert client.post(
        "/api/auth/login", json={"username": "admin", "password": "admin-password"}
    ).status_code == 200
    assert client.put("/api/system/settings/chatbot", json={"enabled": "true"}).status_code == 400
    assert client.put("/api/system/settings/chatbot", json={"enabled": False}).status_code == 200
    assert client.put("/api/system/settings/chatbot", json={"enabled": True}).status_code == 200
    with Repository(db) as repo:
        events = repo.list_payloads("audit_events")
    event_types = {str(event.get("event_type")) for event in events}
    assert "chatbot.global_disabled" in event_types
    assert "chatbot.global_enabled" in event_types


def test_admin_user_toggle_audits_only_real_transitions(tmp_path: Path, monkeypatch):
    client, db = _admin_client(tmp_path, monkeypatch)
    assert client.post(
        "/api/auth/login", json={"username": "admin", "password": "admin-password"}
    ).status_code == 200
    payload = {
        "username": "alice", "role": "OPERATOR", "scopes": [],
        "chatbot_access_enabled": True,
    }
    assert client.post("/api/system/users", json=payload).status_code == 200
    assert client.post("/api/system/users", json=payload).status_code == 200
    payload["chatbot_access_enabled"] = False
    assert client.post("/api/system/users", json=payload).status_code == 200
    with Repository(db) as repo:
        events = repo.list_payloads("audit_events")
    assert sum(event.get("event_type") == "chatbot.user_enabled" for event in events) == 1
    assert sum(event.get("event_type") == "chatbot.user_disabled" for event in events) == 1


def test_system_overview_never_returns_openai_key(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("EARE_OPENAI_API_KEY", "super-secret-test-key")
    client, _ = _admin_client(tmp_path, monkeypatch)
    assert client.post(
        "/api/auth/login", json={"username": "admin", "password": "admin-password"}
    ).status_code == 200
    body = client.get("/api/system").json()
    assert "super-secret-test-key" not in str(body)
