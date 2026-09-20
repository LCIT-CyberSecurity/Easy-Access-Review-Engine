import sqlite3
import tempfile
from dataclasses import asdict
from pathlib import Path

try:
    from fastapi.testclient import TestClient
except ModuleNotFoundError:
    TestClient = None

from access_review_engine.api import create_app
from access_review_engine.access_context import save_access_enrichment
from access_review_engine.domain import (
    Access,
    AccessAssignment,
    AccessRelation,
    AccessRelationType,
    Campaign,
    ControlObject,
    GoldenSourceAssignment,
    Identity,
    IdentityStatus,
    IdentityType,
    Origin,
    OwnerRef,
    Permission,
    Provider,
)
from access_review_engine.services import create_golden_source, create_golden_version, create_snapshot
from access_review_engine.storage import Repository
from access_review_engine.system_admin import init_system, upsert_user


def _seed(db: Path) -> None:
    with Repository(db) as repo:
        repo.upsert("providers", {"id": "finance", "name": "finance", "type": "generic", "display_name": "Finance"})
        for review_id, identity, provider, reviewer in (("review-finance", "alice", "finance", "owner"), ("review-support", "bob", "support", "other")):
            repo.upsert("review_items", {"id": review_id, "campaign_id": "campaign-1", "identity_provider": "ad", "identity_identifier": identity, "identity_status": "active", "access_provider": provider, "access_name": "resource", "control_object": {}, "permission": {}, "target": None, "description": None, "origin": None, "expected": True, "observed": True, "classification": "match", "findings": [], "account_owner": None, "access_owner": None, "reviewer": {"provider": "ad", "identity": reviewer}})
        repo.upsert(
            "campaigns",
            {
                "id": "campaign-1",
                "name": "Campaign",
                "snapshot_id": "snapshot-1",
                "status": "open",
                "scope": {"type": "all"},
            },
        )
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


def _operator_client(db: Path) -> TestClient:
    app = create_app(str(db))
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    init_system(conn)
    upsert_user(conn, {"username": "operator", "role": "OPERATOR", "password": "operator-password"})
    conn.close()
    client = TestClient(app)
    _login(client, "operator", "operator-password")
    return client


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


    def test_web_source_configuration_is_validated_and_persisted_without_plaintext_secrets(tmp_path):
        db = tmp_path / "sources.db"
        app = create_app(str(db))
        conn = sqlite3.connect(db)
        conn.row_factory = sqlite3.Row
        init_system(conn)
        upsert_user(conn, {"username": "source-admin", "role": "ADMIN", "password": "admin-password"})
        conn.close()
        client = TestClient(app)
        _login(client, "source-admin", "admin-password")
        payload = {"provider": "corp-ad", "type": "active_directory", "connection": {"server": "dc01.example.test"}, "collection": {"timeout": 60, "allow_partial": False}, "credentials": {"password_env": "LDAP_PASSWORD"}}
        saved = client.post("/api/system/sources", json=payload)
        assert saved.status_code == 200
        assert client.get("/api/system/sources").json()["sources"][0]["provider"] == "corp-ad"
        assert (tmp_path / "connectors" / "corp-ad.yaml").is_file()
        assert "password: secret" not in (tmp_path / "connectors" / "corp-ad.yaml").read_text().lower()
        invalid = client.post("/api/system/sources", json={**payload, "credentials": {"password": "secret"}})
        assert invalid.status_code == 400


    def test_campaign_promotion_rejects_missing_golden_reference_when_multiple_sources_exist():
        db = Path(tempfile.mkstemp(prefix="eare-promotion-", suffix=".db")[1])
        app = create_app(str(db))
        conn = sqlite3.connect(db)
        conn.row_factory = sqlite3.Row
        init_system(conn)
        upsert_user(conn, {"username": "operator", "role": "OPERATOR", "password": "operator-password"})
        conn.close()
        with Repository(db) as repo:
            for source_id, version_id, name in (("source-a", "version-a", "A"), ("source-b", "version-b", "B")):
                repo.upsert("golden_sources", {"id": source_id, "name": name, "display_name": name, "active_version_id": version_id})
                repo.upsert("golden_source_versions", {"id": version_id, "golden_source_id": source_id, "version": 1, "source_type": "snapshot", "checksum": version_id, "assignments": []})
            repo.upsert("campaigns", {"id": "closed-campaign", "name": "Closed", "snapshot_id": "snapshot-1", "status": "closed", "scope": {"type": "all"}, "golden_source_version_id": None})
        client = TestClient(app)
        _login(client, "operator", "operator-password")
        response = client.post("/api/campaigns/closed-campaign/promote")
        assert response.status_code == 409
        assert response.json()["detail"] == "Campaign has no unambiguous Golden Source reference."


    def test_campaign_preview_rejects_empty_provider_scope_but_draft_can_be_saved(tmp_path):
        db = tmp_path / "draft.db"
        client = _operator_client(db)
        snapshot = create_snapshot(
            [Provider("corp", "generic")],
            [Identity("corp", "alice", IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE)],
            [],
            [Access("staff", "corp")],
            [AccessAssignment("corp", "staff", "corp", "alice", Origin("direct", True, False))],
            [],
        )
        with Repository(db) as repo:
            repo.upsert("snapshots", asdict(snapshot))
        payload = {
            "name": "Scoped draft",
            "snapshot_id": snapshot.id,
            "scope": {"type": "providers", "values": []},
        }
        assert client.post("/api/campaigns/preview", json=payload).status_code == 400
        saved = client.post("/api/campaigns", json=payload)
        assert saved.status_code == 200
        assert saved.json()["status"] == "draft"


    def test_campaign_detail_metrics_cover_more_than_five_hundred_reviews(tmp_path):
        db = tmp_path / "large.db"
        client = _operator_client(db)
        with Repository(db) as repo:
            repo.upsert("campaigns", {"id": "large", "name": "Large", "snapshot_id": "snapshot", "scope": {"type": "all"}})
            for index in range(505):
                item_id = f"review-{index}"
                repo.upsert("review_items", {"id": item_id, "campaign_id": "large", "findings": []})
                if index < 501:
                    repo.insert_append_only("decisions", {"id": f"decision-{index}", "review_item_id": item_id, "value": "approve", "created_at": f"2026-01-01T00:{index // 60:02d}:{index % 60:02d}Z"})
        response = client.get("/api/campaigns/large")
        assert response.status_code == 200
        assert response.json()["campaign"]["review_items"] == 505
        assert response.json()["campaign"]["pending"] == 4
        assert len(response.json()["reviews"]) == 505


    def test_golden_from_scratch_creates_an_immutable_empty_version(tmp_path):
        db = tmp_path / "empty-golden.db"
        client = _operator_client(db)
        response = client.post("/api/golden-sources/from-scratch", json={"name": "future-state"})
        assert response.status_code == 200
        first = response.json()["version"]
        assert first["version"] == 1
        assert first["source_type"] == "from_scratch"
        assert first["assignments"] == []
        with Repository(db) as repo:
            stored = repo.get_payload("golden_source_versions", first["id"])
        assert stored is not None
        assert stored["assignments"] == []
        assert stored["checksum"] == first["checksum"]


    def test_identity_and_access_details_do_not_duplicate_direct_as_effective(tmp_path):
        db = tmp_path / "access-paths.db"
        client = _operator_client(db)
        identity = Identity("corp", "alice", IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE)
        direct_access = Access("support-role", "crm")
        effective_access = Access("ticket-reader", "crm")
        assignment = AccessAssignment(
            "crm",
            "support-role",
            "corp",
            "alice",
            Origin("direct", True, False),
        )
        relation = AccessRelation(
            "crm",
            "support-role",
            "crm",
            "ticket-reader",
            AccessRelationType.GRANTS,
            Origin("role", False, True),
        )
        snapshot = create_snapshot(
            [Provider("crm", "generic")],
            [identity],
            [],
            [direct_access, effective_access],
            [assignment],
            ["import"],
            access_relations=[relation],
        )
        with Repository(db) as repo:
            repo.upsert("identities", identity)
            repo.upsert("snapshots", snapshot)

        response = client.get(f"/api/identities/{identity.id}/accesses")
        assert response.status_code == 200
        payload = response.json()
        assert {row["access_name"] for row in payload["accesses"]} == {"support-role"}
        assert {row["access_name"] for row in payload["effective_accesses"]} == {"ticket-reader"}

        direct_holders = client.get("/api/accesses/crm/support-role/holders").json()
        effective_holders = client.get("/api/accesses/crm/ticket-reader/holders").json()
        assert len(direct_holders["holders"]) == 1
        assert direct_holders["effective_holders"] == []
        assert effective_holders["holders"] == []
        assert len(effective_holders["effective_holders"]) == 1


    def test_access_enrichment_routes_enforce_provider_scope_and_keep_404(tmp_path):
        db = tmp_path / "enrichment-scope.db"
        app = create_app(str(db))
        conn = sqlite3.connect(db)
        conn.row_factory = sqlite3.Row
        init_system(conn)
        upsert_user(conn, {"username": "scope-admin", "role": "ADMIN", "password": "admin-password"})
        upsert_user(conn, {"username": "scope-operator", "role": "OPERATOR", "scopes": ["provider-a"], "password": "operator-password"})
        conn.close()
        with Repository(db) as repo:
            repo.upsert("accesses", {"id": "access-a", "provider": "provider-a", "name": "A", "metadata": {}})
            repo.upsert("accesses", {"id": "access-b", "provider": "provider-b", "name": "B", "metadata": {}})
        client = TestClient(app)
        _login(client, "scope-admin", "admin-password")
        assert client.get("/api/accesses/access-b/enrichment").status_code == 200
        assert client.put("/api/accesses/access-b/enrichment", json={"application": "Sage"}).status_code == 200
        client.cookies.clear()
        _login(client, "scope-operator", "operator-password")
        assert client.get("/api/accesses/access-a/enrichment").status_code == 200
        assert client.put("/api/accesses/access-a/enrichment", json={"application": "Finance"}).status_code == 200
        assert client.get("/api/accesses/access-b/enrichment").status_code == 403
        assert client.put("/api/accesses/access-b/enrichment", json={"application": "Other"}).status_code == 403
        assert client.get("/api/accesses/missing/enrichment").status_code == 404
        assert client.put("/api/accesses/missing/enrichment", json={"application": "No access"}).status_code == 404


    def test_identity_access_and_access_holders_routes_enforce_provider_scope(tmp_path):
        db = tmp_path / "detail-route-scopes.db"
        app = create_app(str(db))
        conn = sqlite3.connect(db)
        conn.row_factory = sqlite3.Row
        init_system(conn)
        upsert_user(conn, {"username": "detail-admin", "role": "ADMIN", "password": "admin-password"})
        upsert_user(conn, {"username": "detail-operator", "role": "OPERATOR", "scopes": ["provider-a"], "password": "operator-password"})
        conn.close()
        identities = [
            Identity("provider-a", "alice", IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE),
            Identity("provider-b", "bob", IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE),
        ]
        snapshot = create_snapshot(
            [Provider("provider-a", "generic"), Provider("provider-b", "generic")],
            identities,
            [],
            [],
            [],
            ["import-a", "import-b"],
        )
        with Repository(db) as repo:
            for identity in identities:
                repo.upsert("identities", identity)
            repo.upsert("snapshots", snapshot)

        client = TestClient(app)
        _login(client, "detail-admin", "admin-password")
        for identity in identities:
            assert client.get(f"/api/identities/{identity.id}/accesses").status_code == 200
        assert client.get("/api/accesses/provider-a/group/holders").status_code == 200
        assert client.get("/api/accesses/provider-b/group/holders").status_code == 200

        client.cookies.clear()
        _login(client, "detail-operator", "operator-password")
        assert client.get(f"/api/identities/{identities[0].id}/accesses").status_code == 200
        assert client.get("/api/identities/bob/accesses").status_code == 403
        assert client.get("/api/accesses/provider-a/group/holders").status_code == 200
        assert client.get("/api/accesses/provider-b/group/holders").status_code == 403
        assert client.get("/api/identities/missing/accesses").status_code == 404


    def test_invalid_golden_assignment_comment_has_no_partial_writes(tmp_path):
        db = tmp_path / "golden-comment-validation.db"
        app = create_app(str(db))
        conn = sqlite3.connect(db)
        conn.row_factory = sqlite3.Row
        init_system(conn)
        upsert_user(conn, {"username": "golden-operator", "role": "OPERATOR", "password": "operator-password"})
        conn.close()
        source = create_golden_source("main")
        assignment = GoldenSourceAssignment("corp", "staff:member", "corp", "alice")
        version = create_golden_version(source, [assignment], "manual")
        source.active_version_id = version.id
        with Repository(db) as repo:
            repo.upsert("golden_sources", source)
            repo.upsert("golden_source_versions", version)
        client = TestClient(app)
        _login(client, "golden-operator", "operator-password")
        payload = {
            "access_provider": "corp",
            "access_name": "staff:member",
            "identity_provider": "corp",
            "identity_identifier": "alice",
            "comment": "x" * 4001,
        }
        response = client.post("/api/golden-sources/main/assignment-comment", json=payload)
        assert response.status_code == 400
        with Repository(db) as repo:
            assert len(repo.list_payloads("golden_source_versions")) == 1
            assert repo.list_payloads("golden_assignment_annotations") == []
            assert repo.get_payload("golden_sources", source.id)["active_version_id"] == version.id
        payload["comment"] = "valid rationale"
        payload["version_comment"] = "x" * 4001
        response = client.post("/api/golden-sources/main/assignment-comment", json=payload)
        assert response.status_code == 400
        with Repository(db) as repo:
            assert len(repo.list_payloads("golden_source_versions")) == 1
            assert repo.list_payloads("golden_assignment_annotations") == []
            assert repo.get_payload("golden_sources", source.id)["active_version_id"] == version.id


    def test_open_campaign_captures_manual_context_and_review_uses_frozen_copy(tmp_path):
        db = tmp_path / "campaign-freeze-api.db"
        client = _operator_client(db)
        identity = Identity("corp", "alice", IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE, native_id="SID-U1")
        access = Access(
            "GG_SAGE_RW:member",
            "corp",
            ControlObject("group", "GG_SAGE_RW", native_id="SID-G1"),
            Permission("member"),
            id="access-stable",
        )
        assignment = AccessAssignment("corp", access.name, "corp", "alice", Origin("group", True, False))
        snapshot = create_snapshot([Provider("corp", "active_directory")], [identity], [], [access], [assignment], [])
        source = create_golden_source("main")
        expected = GoldenSourceAssignment("corp", access.name, "corp", "alice", access_native_id="SID-G1", access_permission="member", identity_native_id="SID-U1")
        version = create_golden_version(source, [expected], "manual")
        source.active_version_id = version.id
        campaign = Campaign(
            "freeze",
            snapshot.id,
            golden_source_version_id=version.id,
            default_reviewer=OwnerRef("corp", "reviewer"),
            allow_unresolved_reviewers=True,
            id="campaign-freeze",
        )
        with Repository(db) as repo:
            repo.upsert("accesses", access)
            repo.upsert("snapshots", snapshot)
            repo.upsert("golden_sources", source)
            repo.upsert("golden_source_versions", version)
            repo.upsert("campaigns", campaign)
            save_access_enrichment(repo, access.id, {"business_permission": "ReadWrite"}, "operator")
        response = client.post(f"/api/campaigns/{campaign.id}/open")
        assert response.status_code == 200
        with Repository(db) as repo:
            assert len(repo.list_payloads("campaign_access_contexts")) == 1
            save_access_enrichment(repo, access.id, {"business_permission": "ReadOnly"}, "operator")
        review = client.get(f"/api/review-items?campaign={campaign.id}")
        assert review.status_code == 200
        row = review.json()["items"][0]
        assert row["business_context"]["manual_context"]["business_permission"]["value"] == "ReadWrite"
        assert row["business_context"]["source_context"] == {}
        assert row["manual_context_capture_status"] == "captured"
