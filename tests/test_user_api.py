from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from access_review_engine.api import create_app
from access_review_engine.domain import GoldenSourceAssignment, Provider
from access_review_engine.services import create_golden_source, create_golden_version, create_snapshot
from access_review_engine.storage import Repository
from access_review_engine.system_admin import external_user_api_enabled, init_system, set_external_user_api_enabled, upsert_user


def _setup(tmp_path: Path) -> tuple[TestClient, Path]:
    db = tmp_path / "user-api.db"
    app = create_app(str(db))
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    init_system(conn)
    upsert_user(conn, {
        "username": "admin", "role": "ADMIN", "password": "administrator-password",
        "must_change_password": False,
    })
    upsert_user(conn, {
        "username": "operator", "role": "OPERATOR", "scopes": ["ad-france"],
        "password": "operator-password", "must_change_password": False, "api_access_enabled": True,
    })
    set_external_user_api_enabled(conn, True)
    conn.close()
    with Repository(db) as repo:
        repo.upsert("providers", {"id": "ad-france", "name": "ad-france", "type": "generic"})
        repo.upsert("providers", {"id": "ad-germany", "name": "ad-germany", "type": "generic"})
    return TestClient(app), db


def _login(client: TestClient, username: str, password: str) -> None:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200


def _issue_key(client: TestClient) -> str:
    _login(client, "operator", "operator-password")
    response = client.post("/api/me/api-token")
    assert response.status_code == 200
    return str(response.json()["api_key"])


def test_api_key_is_hash_only_rotatable_and_never_authenticates_internal_routes(tmp_path):
    client, db = _setup(tmp_path)
    key_a = _issue_key(client)
    assert key_a.startswith("eare_pat_")
    status = client.get("/api/me/api-token").json()
    assert status["api_access_enabled"] is True
    assert status["external_user_api_enabled"] is True
    assert "api_key" not in status

    conn = sqlite3.connect(db)
    row = conn.execute("SELECT token_hash, token_prefix, created_at, expires_at FROM api_tokens").fetchone()
    assert row is not None
    assert row[0] == hashlib.sha256(key_a.encode()).hexdigest()
    assert key_a.encode() not in db.read_bytes()
    created, expires = datetime.fromisoformat(row[2]), datetime.fromisoformat(row[3])
    assert timedelta(days=89, hours=23) < expires - created <= timedelta(days=90)
    assert row[1] == key_a[:16]
    conn.close()

    external = TestClient(client.app)
    headers_a = {"Authorization": f"Bearer {key_a}"}
    me = external.get("/api/v1/me", headers=headers_a)
    assert me.status_code == 200
    assert me.json()["role"] == "OPERATOR"
    assert me.json()["authorized_domains"] == ["ad-france"]

    for method, path, body in (
        ("post", "/api/review-items/nonexistent/decision", {"value": "approve"}),
        ("post", "/api/golden-sources/from-scratch", {"name": "new"}),
        ("post", "/api/campaigns", {"name": "new"}),
        ("post", "/api/system/users", {"username": "other", "role": "ADMIN"}),
        ("post", "/api/system/sources", {"provider": "x"}),
    ):
        response = getattr(external, method)(path, headers=headers_a, json=body)
        assert response.status_code == 401

    key_b_response = client.post("/api/me/api-token")
    assert key_b_response.status_code == 200
    assert key_b_response.headers["cache-control"] == "no-store"
    key_b = key_b_response.json()["api_key"]
    assert key_b.encode() not in db.read_bytes()
    admin = TestClient(client.app)
    _login(admin, "admin", "administrator-password")
    admin_view = admin.get("/api/system").json()
    assert "api_key" not in str(admin_view)
    assert "token_hash" not in str(admin_view)
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT COUNT(*) FROM api_tokens WHERE revoked_at IS NULL").fetchone()[0] == 1
    conn.close()
    assert external.get("/api/v1/me", headers=headers_a).status_code == 401
    assert external.get("/api/v1/me", headers={"Authorization": f"Bearer {key_b}"}).status_code == 200
    assert client.delete("/api/me/api-token").json()["revoked"] is True
    assert external.get("/api/v1/me", headers={"Authorization": f"Bearer {key_b}"}).status_code == 401


def test_global_user_and_expiration_switches_are_checked_on_each_request(tmp_path):
    client, db = _setup(tmp_path)
    _login(client, "admin", "administrator-password")
    operator_client = TestClient(client.app)
    key = _issue_key(operator_client)
    external = TestClient(client.app)
    headers = {"Authorization": f"Bearer {key}"}
    assert external.get("/api/v1/me", headers=headers).status_code == 200

    assert client.put("/api/system/settings/external-user-api", json={"enabled": False}).status_code == 200
    assert external.get("/api/v1/me", headers=headers).status_code == 401
    assert client.get("/api/me").status_code == 200
    assert client.put("/api/system/settings/external-user-api", json={"enabled": True}).status_code == 200
    assert external.get("/api/v1/me", headers=headers).status_code == 200

    user = next(row for row in client.get("/api/system").json()["users"] if row["username"] == "operator")
    payload = {key: user[key] for key in ("username", "display_name", "role", "scopes", "enabled", "api_access_enabled", "auth_source", "external_id") if key in user}
    payload["api_access_enabled"] = False
    assert client.post("/api/system/users", json=payload).status_code == 200
    assert external.get("/api/v1/me", headers=headers).status_code == 401
    conn = sqlite3.connect(db)
    revoked = conn.execute("SELECT revoked_at FROM api_tokens").fetchone()[0]
    assert revoked is not None
    conn.close()

    payload["api_access_enabled"] = True
    assert client.post("/api/system/users", json=payload).status_code == 200
    operator_client.cookies.clear()
    key_expiring = _issue_key(operator_client)
    conn = sqlite3.connect(db)
    expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    conn.execute("UPDATE api_tokens SET expires_at = ? WHERE revoked_at IS NULL", (expired,))
    conn.commit()
    conn.close()
    assert external.get("/api/v1/me", headers={"Authorization": f"Bearer {key_expiring}"}).status_code == 401


def test_external_api_rechecks_current_provider_scopes_and_historical_campaign_access(tmp_path):
    client, db = _setup(tmp_path)
    _login(client, "admin", "administrator-password")
    with Repository(db) as repo:
        repo.upsert("campaigns", {
            "id": "cross-campaign", "name": "Cross provider", "snapshot_id": "missing",
            "status": "open", "scope": {"type": "providers", "values": ["ad-france"]},
        })
        repo.upsert("review_items", {
            "id": "cross-review", "campaign_id": "cross-campaign", "access_provider": "ad-france",
            "access_name": "staff", "identity_provider": "openldap-corp", "identity_identifier": "alice",
            "findings": [],
        })
    operator_client = TestClient(client.app)
    key = _issue_key(operator_client)
    external = TestClient(client.app)
    headers = {"Authorization": f"Bearer {key}"}
    assert external.get("/api/v1/campaigns/cross-campaign", headers=headers).status_code == 403
    assert external.get("/api/v1/campaigns", headers=headers).json()["items"] == []

    user = next(row for row in client.get("/api/system").json()["users"] if row["username"] == "operator")
    payload = {key: user[key] for key in ("username", "display_name", "role", "scopes", "enabled", "api_access_enabled", "auth_source", "external_id") if key in user}
    payload["scopes"] = ["ad-france", "openldap-corp"]
    # Directory scope validation uses configured/observed providers; register the identity domain.
    with Repository(db) as repo:
        repo.upsert("providers", {"id": "openldap-corp", "name": "openldap-corp", "type": "openldap"})
    assert client.post("/api/system/users", json=payload).status_code == 200
    assert external.get("/api/v1/campaigns/cross-campaign", headers=headers).status_code == 200
    assert [row["id"] for row in external.get("/api/v1/campaigns", headers=headers).json()["items"]] == ["cross-campaign"]
    summary = external.get("/api/v1/campaigns/cross-campaign/summary", headers=headers)
    assert summary.status_code == 200
    assert summary.json()["summary"]["total"] == 1
    reviews = external.get("/api/v1/campaigns/cross-campaign/review-items", headers=headers)
    assert reviews.status_code == 200
    assert [row["id"] for row in reviews.json()["items"]] == ["cross-review"]
    assert external.get("/api/v1/review-items/cross-review", headers=headers).status_code == 200


def test_public_swagger_is_read_only_and_hides_internal_routes(tmp_path):
    client, _ = _setup(tmp_path)
    assert client.get("/swagger").status_code == 200
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert schema["paths"]
    assert all(path.startswith("/api/v1/") for path in schema["paths"])
    assert "/api/system" not in schema["paths"]
    assert "/api/review-items/{review_item_id}/decision" not in schema["paths"]
    assert all(set(operations) <= {"get"} for operations in schema["paths"].values())
    assert "BearerToken" in schema["components"]["securitySchemes"]


def test_public_swagger_is_hidden_when_external_user_api_is_disabled(tmp_path):
    client, db = _setup(tmp_path)
    conn = sqlite3.connect(db)
    set_external_user_api_enabled(conn, False)
    conn.close()

    assert client.get("/swagger").status_code == 404
    assert client.get("/openapi.json").status_code == 404



def test_group_owner_and_business_admin_keep_existing_read_boundaries(tmp_path):
    client, db = _setup(tmp_path)
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    upsert_user(conn, {
        "username": "reviewer", "role": "GROUP_OWNER", "password": "reviewer-password",
        "must_change_password": False, "api_access_enabled": True,
    })
    upsert_user(conn, {
        "username": "business", "role": "BUSINESS_ADMIN", "scopes": ["ad-france"],
        "password": "business-password", "must_change_password": False, "api_access_enabled": True,
    })
    conn.close()
    with Repository(db) as repo:
        repo.upsert("campaigns", {
            "id": "owner-campaign", "name": "Owner campaign", "snapshot_id": "missing",
            "status": "open", "scope": {"type": "providers", "values": ["ad-france"]},
        })
        for review_id, identity, reviewer in (
            ("assigned-review", "alice", "reviewer"),
            ("other-review", "bob", "someone-else"),
        ):
            repo.upsert("review_items", {
                "id": review_id, "campaign_id": "owner-campaign", "identity_provider": "ad-france",
                "identity_identifier": identity, "access_provider": "ad-france", "access_name": "staff",
                "reviewer": {"provider": "eare", "identity": reviewer}, "findings": [],
            })
    owner = TestClient(client.app)
    owner_key = _issue_key_as(owner, "reviewer", "reviewer-password")
    owner_api = TestClient(client.app)
    owner_headers = {"Authorization": f"Bearer {owner_key}"}
    assert owner_api.get("/api/v1/campaigns/owner-campaign", headers=owner_headers).status_code == 403
    own_list = owner_api.get("/api/v1/campaigns/owner-campaign/review-items", headers=owner_headers)
    assert own_list.status_code == 200
    assert [row["id"] for row in own_list.json()["items"]] == ["assigned-review"]
    assert owner_api.get("/api/v1/review-items/assigned-review", headers=owner_headers).status_code == 200
    assert owner_api.get("/api/v1/review-items/other-review", headers=owner_headers).status_code == 403

    business = TestClient(client.app)
    business_key = _issue_key_as(business, "business", "business-password")
    business_api = TestClient(client.app)
    business_headers = {"Authorization": f"Bearer {business_key}"}
    assert business_api.get("/api/v1/me", headers=business_headers).status_code == 200
    assert business_api.get("/api/v1/campaigns", headers=business_headers).status_code == 403
    assert business_api.get("/api/v1/golden-sources", headers=business_headers).status_code == 403


def _issue_key_as(client: TestClient, username: str, password: str) -> str:
    _login(client, username, password)
    response = client.post("/api/me/api-token")
    assert response.status_code == 200
    return str(response.json()["api_key"])


def test_golden_sources_are_scoped_and_version_assignments_are_paginated(tmp_path):
    client, db = _setup(tmp_path)
    assignments = [
        GoldenSourceAssignment("ad-france", "GG_FINANCE_RW", "ad-france", "alice"),
        GoldenSourceAssignment("ad-france", "GG_FINANCE_RO", "ad-france", "bob"),
    ]
    source = create_golden_source("Finance")
    version = create_golden_version(source, assignments, "manual", comment="Reviewed baseline")
    source.active_version_id = version.id
    other_source = create_golden_source("Germany")
    other_version = create_golden_version(
        other_source,
        [GoldenSourceAssignment("ad-germany", "GG_SAP", "ad-germany", "carol")],
        "manual",
    )
    other_source.active_version_id = other_version.id
    with Repository(db) as repo:
        repo.upsert("golden_sources", source)
        repo.upsert("golden_source_versions", version)
        repo.upsert("golden_sources", other_source)
        repo.upsert("golden_source_versions", other_version)

    operator = TestClient(client.app)
    key = _issue_key(operator)
    api = TestClient(client.app)
    headers = {"Authorization": f"Bearer {key}"}
    listed = api.get("/api/v1/golden-sources", headers=headers)
    assert listed.status_code == 200
    assert [row["name"] for row in listed.json()["items"]] == ["Finance"]
    assert "assignments" not in api.get(f"/api/v1/golden-sources/{source.id}", headers=headers).json()["active_version"]
    detail = api.get(
        f"/api/v1/golden-sources/{source.id}/versions/{version.id}?limit=1", headers=headers
    )
    assert detail.status_code == 200
    assert detail.json()["total_assignments"] == 2
    assert len(detail.json()["assignments"]) == 1
    assert detail.json()["version"]["comment"] == "Reviewed baseline"
    assert api.get(f"/api/v1/golden-sources/{other_source.id}", headers=headers).status_code == 403


def test_legacy_system_database_migrates_with_external_api_disabled(tmp_path):
    db = tmp_path / "legacy-system.db"
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE system_users (
        id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL,
        role TEXT NOT NULL, scopes TEXT NOT NULL DEFAULT '[]', enabled INTEGER NOT NULL DEFAULT 1,
        password_hash TEXT, must_change_password INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
    )""")
    conn.execute("INSERT INTO system_users(id,username,display_name,role,created_at) VALUES('old','old','Old','OPERATOR','2026-01-01')")
    init_system(conn)
    user = conn.execute("SELECT api_access_enabled FROM system_users WHERE id='old'").fetchone()
    assert user["api_access_enabled"] == 0
    assert conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='api_tokens'").fetchone()
    assert conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='system_settings'").fetchone()
    assert external_user_api_enabled(conn) is False
    conn.close()



def test_historical_all_scope_api_requires_snapshot_and_review_item_domains(tmp_path):
    client, db = _setup(tmp_path)
    with Repository(db) as repo:
        snapshot = create_snapshot(
            [Provider("ad-france", "generic"), Provider("ad-germany", "generic")], [], [], [], [], []
        )
        repo.upsert("snapshots", snapshot)
        for status in ("open", "closed"):
            campaign_id = f"all-{status}"
            repo.upsert("campaigns", {
                "id": campaign_id, "name": campaign_id, "snapshot_id": snapshot.id,
                "status": status, "scope": {"type": "all"},
            })
            repo.upsert("review_items", {
                "id": f"review-{status}", "campaign_id": campaign_id,
                "access_provider": "ad-france", "access_name": "staff",
                "identity_provider": "ad-france", "identity_identifier": "alice", "findings": [],
            })
    operator = TestClient(client.app)
    key = _issue_key(operator)
    api = TestClient(client.app)
    headers = {"Authorization": f"Bearer {key}"}
    for status in ("open", "closed"):
        assert api.get(f"/api/v1/campaigns/all-{status}", headers=headers).status_code == 403
    conn = sqlite3.connect(db)
    conn.execute("UPDATE system_users SET scopes = ? WHERE username = 'operator'", ('["ad-france", "ad-germany"]',))
    conn.commit()
    conn.close()
    for status in ("open", "closed"):
        assert api.get(f"/api/v1/campaigns/all-{status}", headers=headers).status_code == 200


def test_disabling_eare_account_revokes_its_api_key(tmp_path):
    client, _ = _setup(tmp_path)
    _login(client, "admin", "administrator-password")
    operator = TestClient(client.app)
    key = _issue_key(operator)
    response = client.post("/api/system/users/operator/disable")
    assert response.status_code == 200
    assert TestClient(client.app).get("/api/v1/me", headers={"Authorization": f"Bearer {key}"}).status_code == 401



def test_administrator_can_revoke_key_without_reading_its_secret(tmp_path):
    client, _ = _setup(tmp_path)
    operator = TestClient(client.app)
    key = _issue_key(operator)
    _login(client, "admin", "administrator-password")
    response = client.post("/api/system/users/operator/api-token/revoke")
    assert response.status_code == 200
    assert response.json()["revoked"] is True
    external = TestClient(client.app)
    assert external.get("/api/v1/me", headers={"Authorization": f"Bearer {key}"}).status_code == 401
    assert "api_key" not in response.text
    assert "token_hash" not in response.text
