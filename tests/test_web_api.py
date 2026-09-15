import sqlite3
import tempfile
from pathlib import Path

try:
    from fastapi.testclient import TestClient
except ModuleNotFoundError:
    TestClient = None

from access_review_engine.api import create_app
from access_review_engine.storage import Repository
from access_review_engine.system_admin import init_system, upsert_user


def _seed(db: Path) -> None:
    with Repository(db) as repo:
        repo.upsert("providers", {"id": "finance", "name": "finance", "type": "generic", "display_name": "Finance"})
        for review_id, identity, provider, reviewer in (("review-finance", "alice", "finance", "owner"), ("review-support", "bob", "support", "other")):
            repo.upsert("review_items", {"id": review_id, "campaign_id": "campaign-1", "identity_provider": "ad", "identity_identifier": identity, "identity_status": "active", "access_provider": provider, "access_name": "resource", "control_object": {}, "permission": {}, "target": None, "description": None, "origin": None, "expected": True, "observed": True, "classification": "match", "findings": [], "account_owner": None, "access_owner": None, "reviewer": {"provider": "ad", "identity": reviewer}})
        repo.upsert("campaigns", {"id": "campaign-1", "name": "Campaign", "scope": {"type": "all"}})
        repo.insert_append_only("remediation_actions", {"id": "action-finance", "review_item_id": "review-finance", "action": "revoke"})
        repo.insert_append_only("remediation_actions", {"id": "action-support", "review_item_id": "review-support", "action": "revoke"})


def _client() -> TestClient:
    db = Path(tempfile.mkstemp(prefix="eare-api-", suffix=".db")[1])
    app = create_app(str(db))
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    init_system(conn)
    upsert_user(conn, {"username": "operator", "role": "OPERATOR", "password": "operator-password"})
    upsert_user(conn, {"username": "owner", "role": "GROUP_OWNER", "password": "owner-password"})
    upsert_user(conn, {"username": "business", "role": "BUSINESS_ADMIN", "scopes": ["finance"], "password": "business-password"})
    conn.close()
    _seed(db)
    return TestClient(app)


def _login(client: TestClient, username: str, password: str) -> None:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200


if TestClient is not None:
    def test_forbidden_roles_cannot_bypass_dashboard_or_campaign_api():
        client = _client()
        _login(client, "owner", "owner-password")
        assert client.get("/api/dashboard").status_code == 403
        assert client.get("/api/campaigns/campaign-1").status_code == 403
        client.cookies.clear()
        _login(client, "business", "business-password")
        assert client.get("/api/dashboard").status_code == 403
        assert client.get("/api/campaigns/campaign-1").status_code == 403


    def test_group_owner_review_scope_and_decision():
        client = _client()
        _login(client, "owner", "owner-password")
        response = client.get("/api/review-items?limit=1&offset=0")
        assert response.status_code == 200
        assert response.json()["total"] == 1
        assert response.json()["items"][0]["id"] == "review-finance"
        assert client.post("/api/review-items/review-finance/decision", json={"value": "approve"}).status_code == 200
        assert client.post("/api/review-items/review-support/decision", json={"value": "approve"}).status_code == 403


    def test_business_admin_sees_only_authorized_remediation_actions():
        client = _client()
        _login(client, "business", "business-password")
        response = client.get("/api/remediation-actions")
        assert response.status_code == 200
        assert [item["id"] for item in response.json()["items"]] == ["action-finance"]


    def test_decision_comment_validation():
        client = _client()
        _login(client, "operator", "operator-password")
        for value in ("revoke", "not_applicable"):
            assert client.post("/api/review-items/review-finance/decision", json={"value": value, "comment": ""}).status_code == 400
            assert client.post("/api/review-items/review-finance/decision", json={"value": value, "comment": "reviewed"}).status_code == 200


    def test_default_admin_bootstrap_login():
        client = _client()
        _login(client, "admin", "admin")
