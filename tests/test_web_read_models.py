from access_review_engine.storage import Repository
from access_review_engine.web_read_models import projected_rows, review_item_view


def test_review_item_view_joins_latest_decision_without_mutating_review_item(tmp_path):
    db = tmp_path / "web.db"
    item = {"id": "review-1", "identity_provider": "ad", "identity_identifier": "alice", "identity_status": "active", "access_provider": "app", "access_name": "admin", "permission": {}, "target": None, "findings": []}
    with Repository(db) as repo:
        repo.upsert("review_items", item)
        repo.insert_append_only("decisions", {"id": "decision-old", "review_item_id": "review-1", "value": "revoke", "created_at": "2026-01-01T00:00:00+00:00"})
        repo.insert_append_only("decisions", {"id": "decision-new", "review_item_id": "review-1", "value": "approve", "created_at": "2026-01-02T00:00:00+00:00"})
        view = review_item_view(repo, item)
        assert view["decision_state"] == "decided"
        assert view["latest_decision"]["value"] == "approve"
        assert "decision" not in item


def test_projected_rows_searches_before_pagination(tmp_path):
    db = tmp_path / "web.db"
    with Repository(db) as repo:
        for identifier in ("alice@example.com", "bob@example.com"):
            repo.upsert("identities", {"id": identifier, "provider": "ad", "identifier": identifier, "status": "active"})
    result = projected_rows(str(db), "identities", limit=1, offset=0, search="alice@example.com")
    assert result["total"] == 1
    assert result["items"][0]["identifier"] == "alice@example.com"


def test_identity_findings_use_latest_snapshot_only(tmp_path):
    db = tmp_path / "identity.db"
    with Repository(db) as repo:
        repo.upsert("identities", {"id": "alice", "provider": "ad", "identifier": "alice", "status": "active"})
        repo.upsert("snapshots", {"id": "old", "created_at": "2026-01-01", "comparison_states": [{"identity_provider": "ad", "identity_identifier": "alice", "findings": ["missing"]}]})
        repo.upsert("snapshots", {"id": "new", "created_at": "2026-01-02", "comparison_states": []})
    assert projected_rows(str(db), "identities", limit=10, offset=0)["items"][0]["finding_count"] == 0


def test_campaign_summary_breakdown_uses_latest_decisions(tmp_path):
    db = tmp_path / "campaign.db"
    with Repository(db) as repo:
        repo.upsert("campaigns", {"id": "campaign-1", "name": "Q1"})
        for index in range(10):
            item_id = f"review-{index}"
            repo.upsert("review_items", {"id": item_id, "campaign_id": "campaign-1", "reviewer": None, "findings": ["finding"] if index == 0 else []})
            if index < 4:
                value = "approve"
            elif index < 6:
                value = "revoke"
            elif index == 6:
                value = "not_applicable"
            else:
                continue
            repo.insert_append_only("decisions", {"id": f"decision-{index}", "review_item_id": item_id, "value": value, "created_at": f"2026-01-{index + 1:02d}"})
    summary = projected_rows(str(db), "campaigns", limit=10, offset=0)["items"][0]
    assert summary["approved"] == 4
    assert summary["revoked"] == 2
    assert summary["not_applicable"] == 1
    assert summary["pending"] == 3
    assert summary["progress"] == 70
    assert summary["findings_count"] == 1


def test_source_summary_uses_latest_snapshot_data(tmp_path):
    db = tmp_path / "sources.db"
    with Repository(db) as repo:
        repo.upsert("providers", {"id": "finance", "name": "finance", "type": "generic", "display_name": "Finance"})
        repo.upsert("snapshots", {
            "id": "snapshot-1", "created_at": "2026-01-02",
            "providers": [{"name": "finance"}],
            "identities": [
                {"provider": "finance", "identifier": "alice", "type": "user"},
                {"provider": "finance", "identifier": "finance-admins", "type": "group"},
            ],
            "access_assignments": [{"provider": "finance", "access_name": "payroll"}],
            "comparison_states": [],
        })
    source = projected_rows(str(db), "providers", limit=10, offset=0)["items"][0]
    assert source["health"] == "healthy"
    assert source["identity_count"] == 2
    assert source["group_count"] == 1
    assert source["access_count"] == 1
    assert source["latest_snapshot"] == "snapshot-1"


def test_remediation_actions_include_review_context_and_campaign_filter(tmp_path):
    db = tmp_path / "web.db"
    with Repository(db) as repo:
        repo.upsert("review_items", {"id": "review-1", "campaign_id": "campaign-a", "identity_identifier": "alice", "identity_provider": "ad", "access_name": "Finance", "access_provider": "finance", "target": "prod"})
        repo.insert_append_only("remediation_actions", {"id": "action-1", "review_item_id": "review-1", "action": "revoke", "status": "pending"})

    result = projected_rows(str(db), "remediation_actions", limit=10, offset=0, campaign="campaign-a")

    assert result["total"] == 1
    assert result["items"][0]["identity_identifier"] == "alice"
    assert result["items"][0]["access_name"] == "Finance"
    assert result["items"][0]["campaign_id"] == "campaign-a"


def test_identity_type_can_be_used_as_status_filter(tmp_path):
    db = tmp_path / "web.db"
    with Repository(db) as repo:
        repo.upsert("identities", {"id": "identity-1", "provider": "ad", "identifier": "alice", "type": "user", "status": "active"})
        repo.upsert("identities", {"id": "identity-2", "provider": "ad", "identifier": "engineering", "type": "group", "status": "active"})

    result = projected_rows(str(db), "identities", limit=10, offset=0, status="group")

    assert [item["id"] for item in result["items"]] == ["identity-2"]


def test_hydrated_identity_owner_is_usable_by_the_comparison():
    """A stored account owner must come back as an OwnerRef, or campaign preview crashes."""
    from access_review_engine.domain import Identity, OwnerRef
    from access_review_engine.services import owner_findings
    from access_review_engine.storage import hydrate_identity

    stored = {
        "provider": "corp", "identifier": "svc-erp", "type": "technical_account", "status": "active",
        "account_owner": {"provider": "corp", "identity": "alice"},
    }
    identity = hydrate_identity(stored)
    assert identity.account_owner == OwnerRef(provider="corp", identity="alice")
    owner = Identity(provider="corp", identifier="alice", type="user_account", status="active")
    assert owner_findings(identity, {("corp", "alice"): owner}) == []
