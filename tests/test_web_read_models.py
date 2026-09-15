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
