from dataclasses import asdict
import sqlite3

from access_review_engine.domain import (
    Access,
    AccessAssignment,
    AccessRelation,
    AccessRelationType,
    Identity,
    IdentityStatus,
    IdentityType,
    Origin,
    Provider,
)
from access_review_engine.services import create_snapshot
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
            "accesses": [{"provider": "finance", "name": "payroll"}],
            "access_assignments": [
                {"provider": "finance", "access_name": "payroll", "identity_identifier": "alice"},
                {"provider": "finance", "access_name": "payroll", "identity_identifier": "bob"},
            ],
            "comparison_states": [],
        })
    source = projected_rows(str(db), "providers", limit=10, offset=0)["items"][0]
    assert source["health"] == "healthy"
    assert source["identity_count"] == 2
    assert source["group_count"] == 1
    assert source["access_count"] == 1
    assert source["latest_snapshot"] == "snapshot-1"


def test_source_summary_attributes_a_failed_sync_to_its_provider(tmp_path):
    db = tmp_path / "failed-source.db"
    with Repository(db) as repo:
        for provider in ("corp-ad", "crm-ldap"):
            repo.upsert("providers", {"id": provider, "name": provider, "type": "generic"})
    with sqlite3.connect(db) as conn:
        conn.execute(
            "CREATE TABLE web_jobs ("
            "id TEXT PRIMARY KEY, kind TEXT, status TEXT, progress TEXT, result TEXT, error TEXT, "
            "created_at TEXT, started_at TEXT, finished_at TEXT)"
        )
        conn.execute(
            "INSERT INTO web_jobs (id, kind, status, progress, result, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("failed", "sync", "FAILED", "Failed", '{"provider": "corp-ad"}', "2026-01-03"),
        )

    sources = {
        row["name"]: row
        for row in projected_rows(str(db), "providers", limit=10, offset=0)["items"]
    }

    assert sources["corp-ad"]["health"] == "failed"
    assert sources["crm-ldap"]["health"] == "never_synced"


def test_source_summary_uses_latest_snapshot_covering_each_provider(tmp_path):
    db = tmp_path / "sources.db"
    with Repository(db) as repo:
        for provider in ("corp-ad", "crm-ldap"):
            repo.upsert("providers", {"id": provider, "name": provider, "type": "generic"})
        repo.upsert("snapshots", {
            "id": "ad-snapshot", "created_at": "2026-01-02T14:00:00Z",
            "providers": [{"name": "corp-ad"}],
            "identities": [{"provider": "corp-ad", "identifier": "alice", "type": "user"}],
            "access_assignments": [], "comparison_states": [],
        })
        repo.upsert("snapshots", {
            "id": "crm-snapshot", "created_at": "2026-01-02T15:31:00Z",
            "providers": [{"name": "crm-ldap"}],
            "identities": [{"provider": "crm-ldap", "identifier": "bob", "type": "user"}],
            "access_assignments": [], "comparison_states": [],
        })
    sources = {row["name"]: row for row in projected_rows(str(db), "providers", limit=10, offset=0)["items"]}
    assert sources["corp-ad"]["latest_snapshot"] == "ad-snapshot"
    assert sources["corp-ad"]["health"] == "healthy"
    assert sources["crm-ldap"]["latest_snapshot"] == "crm-snapshot"


def test_snapshot_picker_counts_real_assignments_and_providers(tmp_path):
    db = tmp_path / "snapshots.db"
    with Repository(db) as repo:
        repo.upsert("snapshots", {
            "id": "snapshot",
            "providers": [{"name": "corp"}, {"name": "crm"}],
            "access_assignments": [{"id": "one"}, {"id": "two"}],
        })

    snapshot = projected_rows(str(db), "snapshots", limit=10, offset=0)["items"][0]

    assert snapshot["assignment_count"] == 2
    assert snapshot["provider_count"] == 2


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


def test_remediation_action_includes_latest_decision_comment_and_author(tmp_path):
    db = tmp_path / "remediation.db"
    with Repository(db) as repo:
        repo.upsert("campaigns", {"id": "campaign-a", "name": "Quarterly access review"})
        repo.upsert("review_items", {"id": "review-1", "campaign_id": "campaign-a"})
        repo.insert_append_only("decisions", {"id": "old", "review_item_id": "review-1", "value": "approve", "comment": None, "decided_by": "old-owner", "created_at": "2026-01-01"})
        repo.insert_append_only("decisions", {"id": "new", "review_item_id": "review-1", "value": "revoke", "comment": "No longer needed", "decided_by": "owner", "created_at": "2026-01-02"})
        repo.insert_append_only("remediation_actions", {"id": "action-1", "review_item_id": "review-1", "action": "revoke", "status": "pending"})
    action = projected_rows(str(db), "remediation_actions", limit=10, offset=0)["items"][0]
    assert action["decision"] == "revoke"
    assert action["comment"] == "No longer needed"
    assert action["decided_by"] == "owner"
    assert action["campaign_name"] == "Quarterly access review"


def test_pending_filter_means_no_latest_decision_and_pending_sorts_first(tmp_path):
    db = tmp_path / "pending.db"
    with Repository(db) as repo:
        for item_id, identity in (("pending", "zoe"), ("decided", "alice")):
            repo.upsert("review_items", {"id": item_id, "campaign_id": "campaign", "identity_identifier": identity, "identity_provider": "corp", "access_provider": "corp", "access_name": "staff", "findings": []})
        repo.insert_append_only("decisions", {"id": "decision", "review_item_id": "decided", "value": "approve", "created_at": "2026-01-01"})
    all_rows = projected_rows(str(db), "review_items", limit=10, offset=0)["items"]
    pending = projected_rows(str(db), "review_items", limit=10, offset=0, status="pending")
    assert [row["id"] for row in all_rows] == ["pending", "decided"]
    assert pending["total"] == 1
    assert pending["items"][0]["id"] == "pending"


def test_access_counts_are_projected_from_real_assignments_and_findings(tmp_path):
    db = tmp_path / "access-counts.db"
    with Repository(db) as repo:
        repo.upsert("accesses", {"id": "access", "provider": "crm", "name": "support"})
        repo.upsert("access_assignments", {"id": "grant", "provider": "crm", "access_name": "support", "identity_provider": "crm", "identity_identifier": "alice"})
        repo.upsert("access_assignments", {"id": "second-path", "provider": "crm", "access_name": "support", "identity_provider": "crm", "identity_identifier": "alice", "origin": {"kind": "nested"}})
        repo.upsert("access_assignments", {"id": "second-holder", "provider": "crm", "access_name": "support", "identity_provider": "crm", "identity_identifier": "bob"})
        repo.upsert("snapshots", {"id": "snapshot", "created_at": "2026-01-01", "providers": [{"name": "crm"}], "comparison_states": [{"access_provider": "crm", "access_name": "support", "findings": ["unexpected"]}]})
    access = projected_rows(str(db), "accesses", limit=10, offset=0)["items"][0]
    assert access["assignment_count"] == 3
    assert access["holder_count"] == 2
    assert access["finding_count"] == 1


def test_review_provenance_uses_campaign_snapshot_access_paths(tmp_path):
    db = tmp_path / "paths.db"
    identity = Identity("corp", "alice", IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE)
    root = Access("crm-support", "crm")
    target = Access("application-users", "crm")
    assignment = AccessAssignment("crm", "crm-support", "corp", "alice", Origin("direct", True, False))
    relation = AccessRelation("crm", "crm-support", "crm", "application-users", AccessRelationType.GRANTS, Origin("group", False, True))
    snapshot = create_snapshot([Provider("crm", "generic")], [identity], [], [root, target], [assignment], ["import"], access_relations=[relation])
    with Repository(db) as repo:
        repo.upsert("snapshots", asdict(snapshot))
        repo.upsert("campaigns", {"id": "campaign", "name": "Q4", "snapshot_id": snapshot.id})
        repo.upsert("review_items", {"id": "direct", "campaign_id": "campaign", "identity_provider": "corp", "identity_identifier": "alice", "access_provider": "crm", "access_name": "crm-support", "findings": []})
        repo.upsert("review_items", {"id": "effective", "campaign_id": "campaign", "identity_provider": "corp", "identity_identifier": "alice", "access_provider": "crm", "access_name": "application-users", "findings": []})
    rows = {row["id"]: row for row in projected_rows(str(db), "review_items", limit=10, offset=0)["items"]}
    assert rows["direct"]["direct"] is True
    assert rows["effective"]["direct"] is False
    assert [step["identifier"] for step in rows["effective"]["paths"][0]["access_chain"]] == ["crm-support", "application-users"]


def test_campaign_aggregates_include_more_than_five_hundred_reviews(tmp_path):
    db = tmp_path / "large-campaign.db"
    with Repository(db) as repo:
        repo.upsert("campaigns", {"id": "campaign", "name": "Large"})
        for index in range(505):
            item_id = f"review-{index}"
            repo.upsert("review_items", {"id": item_id, "campaign_id": "campaign", "findings": []})
            if index < 501:
                repo.insert_append_only("decisions", {"id": f"decision-{index}", "review_item_id": item_id, "value": "approve", "created_at": f"2026-01-01T00:{index // 60:02d}:{index % 60:02d}Z"})
    campaign = projected_rows(str(db), "campaigns", limit=10, offset=0)["items"][0]
    assert campaign["review_items"] == 505
    assert campaign["approved"] == 501
    assert campaign["pending"] == 4


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


def test_review_items_carry_the_names_people_recognise(tmp_path):
    """LDAP collectors identify objects by native id; screens must show the readable name."""
    db = tmp_path / "names.db"
    with Repository(db) as repo:
        repo.insert_append_only("identities", {"id": "i1", "provider": "crm-ldap", "identifier": "entry:uuid-1", "display_name": "Alice Martin", "type": "user_account", "status": "active"})
        repo.insert_append_only("accesses", {"id": "a1", "provider": "crm-ldap", "name": "group:uuid-9:member", "display_name": "CRM-Support:member"})
        repo.insert_append_only("review_items", {"id": "review-1", "campaign_id": "campaign-a", "identity_provider": "crm-ldap", "identity_identifier": "entry:uuid-1", "access_provider": "crm-ldap", "access_name": "group:uuid-9:member", "findings": []})
        repo.insert_append_only("remediation_actions", {"id": "action-1", "review_item_id": "review-1", "action": "revoke", "status": "pending"})
    row = projected_rows(str(db), "review_items", limit=10, offset=0)["items"][0]
    assert row["identity_display_name"] == "Alice Martin"
    assert row["access_display_name"] == "CRM-Support:member"
    assert row["identity"]["display_name"] == "Alice Martin"
    action = projected_rows(str(db), "remediation_actions", limit=10, offset=0)["items"][0]
    assert action["identity_display_name"] == "Alice Martin"


def test_rows_can_be_sorted_on_a_column_with_empty_values_last(tmp_path):
    db = tmp_path / "sort.db"
    with Repository(db) as repo:
        for identifier, count in (("b-user", 5), ("a-user", 50), ("c-user", None)):
            repo.insert_append_only("identities", {"id": identifier, "provider": "corp", "identifier": identifier, "display_name": identifier.upper(), "type": "user_account", "status": "active", "seats": count})
    ascending = [row["identifier"] for row in projected_rows(str(db), "identities", limit=10, offset=0, sort="seats")["items"]]
    assert ascending == ["b-user", "a-user", "c-user"]
    descending = [row["identifier"] for row in projected_rows(str(db), "identities", limit=10, offset=0, sort="seats", order="desc")["items"]]
    assert descending[0] == "a-user"
    unknown = [row["identifier"] for row in projected_rows(str(db), "identities", limit=10, offset=0, sort="nothing")["items"]]
    assert unknown == ["a-user", "b-user", "c-user"]


def test_scoped_campaign_and_review_projections_hide_disallowed_campaigns(tmp_path):
    from access_review_engine.storage import Repository
    from access_review_engine.web_read_models import projected_rows

    db = tmp_path / "campaign-page-scope.db"
    with Repository(db) as repo:
        for campaign_id in ("france", "germany"):
            repo.upsert("campaigns", {"id": campaign_id, "name": campaign_id, "snapshot_id": "snapshot", "scope": {"type": "all"}})
            item_id = f"review-{campaign_id}"
            repo.upsert("review_items", {
                "id": item_id,
                "campaign_id": campaign_id,
                "identity_provider": campaign_id,
                "identity_identifier": "alice",
                "access_provider": campaign_id,
                "access_name": "staff",
                "findings": [],
            })
            repo.insert_append_only("decisions", {"id": f"decision-{campaign_id}", "review_item_id": item_id, "value": "approve", "created_at": "2026-01-01T00:00:00Z"})

    allowed = {"france"}
    campaign_page = projected_rows(str(db), "campaigns", limit=20, offset=0, allowed_campaign_ids=allowed)
    assert [row["id"] for row in campaign_page["items"]] == ["france"]
    assert campaign_page["total"] == 1
    review_page = projected_rows(str(db), "review_items", limit=20, offset=0, allowed_campaign_ids=allowed)
    assert [row["id"] for row in review_page["items"]] == ["review-france"]
    decisions = projected_rows(str(db), "decisions", limit=20, offset=0, allowed_campaign_ids=allowed)
    assert [row["id"] for row in decisions["items"]] == ["decision-france"]


def test_operator_provider_projection_sanitizes_snapshots_and_filters_accesses(tmp_path):
    from access_review_engine.storage import Repository
    from access_review_engine.web_read_models import projected_rows

    db = tmp_path / "provider-page-scope.db"
    with Repository(db) as repo:
        repo.upsert("providers", {"id": "france", "name": "france", "type": "generic"})
        repo.upsert("providers", {"id": "germany", "name": "germany", "type": "generic"})
        repo.upsert("accesses", {"id": "access-fr", "provider": "france", "name": "staff"})
        repo.upsert("accesses", {"id": "access-de", "provider": "germany", "name": "staff"})
        repo.upsert("snapshots", {
            "id": "snapshot",
            "created_at": "2026-01-01T00:00:00Z",
            "immutable": True,
            "checksum": "checksum",
            "providers": [{"name": "france"}, {"name": "germany"}],
            "identities": [{"provider": "france", "identifier": "alice"}, {"provider": "germany", "identifier": "bob"}],
            "accesses": [{"provider": "france", "name": "staff"}, {"provider": "germany", "name": "staff"}],
            "access_assignments": [
                {"provider": "france", "access_name": "staff", "identity_provider": "france", "identity_identifier": "alice"},
                {"provider": "germany", "access_name": "staff", "identity_provider": "germany", "identity_identifier": "bob"},
                {"provider": "france", "access_name": "staff", "identity_provider": "germany", "identity_identifier": "bob"},
            ],
            "resources": [],
            "source_import_ids": [],
        })

    allowed = {"france"}
    providers = projected_rows(str(db), "providers", limit=20, offset=0, allowed_providers=allowed)
    assert [row["name"] for row in providers["items"]] == ["france"]
    accesses = projected_rows(str(db), "accesses", limit=20, offset=0, allowed_providers=allowed)
    assert [row["id"] for row in accesses["items"]] == ["access-fr"]
    snapshots = projected_rows(str(db), "snapshots", limit=20, offset=0, allowed_providers=allowed)
    row = snapshots["items"][0]
    assert row["provider_count"] == 1
    assert row["assignment_count"] == 1
    assert row["providers"] == [{"name": "france"}]
    assert "identities" not in row and "access_assignments" not in row and "accesses" not in row
