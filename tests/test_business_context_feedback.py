from __future__ import annotations

import sqlite3

from fastapi.testclient import TestClient

from access_review_engine.api import create_app
from access_review_engine.storage import Repository
from access_review_engine.system_admin import init_system, upsert_user


def _fixture(tmp_path):
    db = tmp_path / "feedback.db"
    app = create_app(str(db))
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    init_system(conn)
    for username, role, scopes in (
        ("admin-test", "ADMIN", []),
        ("france-op", "OPERATOR", ["ad-france"]),
        ("owner-test", "GROUP_OWNER", []),
        ("other-owner", "GROUP_OWNER", []),
        ("business-test", "BUSINESS_ADMIN", ["ad-france"]),
        ("remediation-test", "REMEDIATION_MANAGER", ["ad-france"]),
    ):
        upsert_user(
            conn,
            {"username": username, "role": role, "scopes": scopes, "password": "test-password"},
        )
    conn.close()
    with Repository(db) as repo:
        for suffix, provider, reviewer in (
            ("fr", "ad-france", "owner-test"),
            ("de", "ad-germany", "other-owner"),
        ):
            repo.upsert(
                "campaigns",
                {
                    "id": f"campaign-{suffix}",
                    "name": suffix,
                    "snapshot_id": "missing-snapshot",
                    "status": "open",
                    "scope": {"type": "providers", "values": [provider]},
                },
            )
            repo.upsert(
                "review_items",
                {
                    "id": f"review-{suffix}",
                    "campaign_id": f"campaign-{suffix}",
                    "access_provider": provider,
                    "access_name": "CRM-Admin",
                    "identity_provider": provider,
                    "identity_identifier": "alice",
                    "reviewer": {"provider": "eare", "identity": reviewer},
                },
            )
        repo.upsert(
            "campaign_access_contexts",
            {"id": "frozen", "campaign_id": "campaign-fr", "business_permission": "read"},
        )
        repo.upsert("access_enrichments", {"id": "enrichment", "business_permission": "read"})
        repo.upsert("golden_source_versions", {"id": "golden-version", "version": 1})
        repo.upsert("snapshot_functional_access_models", {"id": "functional-model", "rights": []})
    return db, TestClient(app)


def _login(client, username):
    client.cookies.clear()
    assert (
        client.post(
            "/api/auth/login", json={"username": username, "password": "test-password"}
        ).status_code
        == 200
    )


def _create(client, review="review-fr", fields=None, comment="Incorrect context"):
    return client.post(
        f"/api/review-items/{review}/business-context-feedback",
        json={"fields": ["application"] if fields is None else fields, "comment": comment},
    )


def test_feedback_role_scope_lifecycle_and_history(tmp_path):
    db, client = _fixture(tmp_path)
    _login(client, "owner-test")
    created = _create(client)
    assert created.status_code == 201, created.text
    row = created.json()
    assert row["status"] == "open" and row["reporter_username"] == "owner-test"
    assert _create(client, "review-de").status_code == 404
    assert _create(client, "unknown-review").status_code == 404
    assert client.get("/api/business-context-feedback").status_code == 403
    assert (
        client.post(
            f"/api/business-context-feedback/{row['id']}/resolve",
            json={"status": "resolved", "resolution_comment": ""},
        ).status_code
        == 403
    )

    _login(client, "france-op")
    assert _create(client).status_code == 201
    assert _create(client, "review-de").status_code == 404
    listing = client.get("/api/business-context-feedback").json()
    assert listing["total"] == 2
    assert client.get("/api/business-context-feedback?campaign=campaign-de").json()["total"] == 0
    assert (
        client.post(
            f"/api/business-context-feedback/{row['id']}/resolve",
            json={"status": "resolved", "resolution_comment": "Checked"},
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/business-context-feedback/{row['id']}/resolve",
            json={"status": "dismissed", "resolution_comment": ""},
        ).status_code
        == 409
    )

    _login(client, "admin-test")
    german = _create(client, "review-de").json()
    assert german["status"] == "open"
    page = client.get("/api/business-context-feedback?status=all&limit=1").json()
    assert page["total"] == 3 and len(page["items"]) == 1
    assert client.get("/api/business-context-feedback?status=all&limit=1&offset=1").json()["items"]
    assert (
        client.post(
            f"/api/business-context-feedback/{german['id']}/resolve",
            json={"status": "dismissed", "resolution_comment": ""},
        ).status_code
        == 200
    )
    _login(client, "france-op")
    assert (
        client.post(
            f"/api/business-context-feedback/{german['id']}/resolve",
            json={"status": "resolved", "resolution_comment": ""},
        ).status_code
        == 404
    )

    with Repository(db) as repo:
        assert (
            repo.get_payload("campaign_access_contexts", "frozen")["business_permission"] == "read"
        )
        assert repo.get_payload("access_enrichments", "enrichment")["business_permission"] == "read"
        assert repo.get_payload("golden_source_versions", "golden-version")["version"] == 1
        functional = repo.get_payload("snapshot_functional_access_models", "functional-model")
        assert functional["rights"] == []
        assert not repo.list_payloads("decisions")
        events = [
            event["event_type"]
            for event in repo.list_payloads("audit_events")
            if event["event_type"].startswith("business_context.feedback_")
        ]
        assert "business_context.feedback_created" in events
        assert "business_context.feedback_resolved" in events
        assert "business_context.feedback_dismissed" in events


def test_feedback_validation_and_denied_roles(tmp_path):
    _, client = _fixture(tmp_path)
    for username in ("business-test", "remediation-test"):
        _login(client, username)
        assert _create(client).status_code == 403
    _login(client, "owner-test")
    assert _create(client, fields=[], comment=" ").status_code == 400
    assert _create(client, fields=["provider_metadata"]).status_code == 400
    assert _create(client, fields=["application", "application"]).status_code == 400
    assert _create(client, comment="x" * 2001).status_code == 400
    assert (
        client.post(
            "/api/review-items/review-fr/business-context-feedback",
            json={"fields": [], "comment": "ok", "raw_metadata": "secret"},
        ).status_code
        == 400
    )
    xss = _create(client, comment="<script>alert(1)</script>")
    assert xss.status_code == 201 and xss.json()["comment"] == "<script>alert(1)</script>"
