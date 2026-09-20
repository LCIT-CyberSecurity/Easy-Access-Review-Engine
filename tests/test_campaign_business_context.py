from __future__ import annotations

from dataclasses import asdict

from access_review_engine.access_context import capture_campaign_access_contexts, save_access_enrichment
from access_review_engine.domain import (
    AccessAssignment,
    ControlObject,
    Identity,
    IdentityStatus,
    IdentityType,
    Origin,
    Permission,
    Provider,
)
from access_review_engine.services import create_snapshot
from access_review_engine.source_mapping import BUSINESS_CONTEXT_METADATA_KEY
from access_review_engine.storage import Repository
from access_review_engine.web_read_models import projected_rows
from access_review_engine.domain import Access


def test_campaign_freezes_one_manual_context_per_access_and_keeps_history(tmp_path) -> None:
    db = tmp_path / "campaign-context.db"
    access = Access(
        "GG_SAGE_RW:member",
        "corp-ad",
        ControlObject("group", "GG_SAGE_RW", native_id="SID-G1"),
        Permission("member"),
        metadata={
            BUSINESS_CONTEXT_METADATA_KEY: {
                "business_permission": {
                    "value": "ReadOnly",
                    "provenance": "source_attribute",
                    "mapping_mode": "configured",
                    "attribute": "extensionAttribute6",
                }
            }
        },
        id="access-stable-1",
    )
    identities = [Identity("corp-ad", f"user-{i}", IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE) for i in range(50)]
    snapshot = create_snapshot(
        [Provider("corp-ad", "active_directory")],
        identities,
        [],
        [access],
        [AccessAssignment("corp-ad", access.name, "corp-ad", "user-0", Origin("group", True, False))],
        ["import-1"],
    )
    with Repository(db) as repo:
        repo.upsert("accesses", access)
        repo.upsert("snapshots", asdict(snapshot))
        save_access_enrichment(repo, access.id, {"business_permission": "ReadWrite"}, "operator")
        assert capture_campaign_access_contexts(repo, "campaign-1", [access] * 50) == 1
        assert len(repo.list_payloads("campaign_access_contexts")) == 1
        assert len(snapshot.access_assignments) == 1

        repo.upsert("campaigns", {"id": "campaign-1", "snapshot_id": snapshot.id, "status": "open"})
        for i in range(50):
            repo.upsert("review_items", {
                "id": f"review-{i}",
                "campaign_id": "campaign-1",
                "identity_provider": "corp-ad",
                "identity_identifier": f"user-{i}",
                "access_provider": "corp-ad",
                "access_name": access.name,
                "findings": [],
            })

        save_access_enrichment(repo, access.id, {"business_permission": "ReadOnly"}, "operator")
        rows = projected_rows(str(db), "review_items", limit=100, offset=0, campaign="campaign-1")["items"]
        assert len(rows) == 50
        assert {row["business_context"]["fields"]["business_permission"]["manual"]["value"] for row in rows} == {"ReadWrite"}
        assert {row["business_context"]["fields"]["business_permission"]["source"]["value"] for row in rows} == {"ReadOnly"}
        assert all(row["business_context"]["fields"]["business_permission"]["conflict"] for row in rows)
        assert all(row["manual_context_capture_status"] == "captured" for row in rows)

        assert capture_campaign_access_contexts(repo, "campaign-2", [access]) == 1
        repo.upsert("campaigns", {"id": "campaign-2", "snapshot_id": snapshot.id, "status": "open"})
        repo.upsert("review_items", {
            "id": "review-new",
            "campaign_id": "campaign-2",
            "identity_provider": "corp-ad",
            "identity_identifier": "user-0",
            "access_provider": "corp-ad",
            "access_name": access.name,
            "findings": [],
        })
        new_row = projected_rows(str(db), "review_items", limit=10, offset=0, campaign="campaign-2")["items"][0]
        assert new_row["business_context"]["fields"]["business_permission"]["manual"]["value"] == "ReadOnly"
        assert len(repo.list_payloads("campaign_access_contexts")) == 2


def test_legacy_campaign_without_frozen_context_does_not_read_live_enrichment(tmp_path) -> None:
    db = tmp_path / "legacy-campaign.db"
    access = Access("staff:member", "corp", ControlObject("group", "staff"), Permission("member"), id="access-legacy")
    snapshot = create_snapshot([Provider("corp", "generic")], [], [], [access], [], [])
    with Repository(db) as repo:
        repo.upsert("accesses", access)
        repo.upsert("snapshots", asdict(snapshot))
        repo.upsert("campaigns", {"id": "legacy", "snapshot_id": snapshot.id, "status": "open"})
        repo.upsert("review_items", {"id": "review", "campaign_id": "legacy", "identity_provider": "corp", "identity_identifier": "alice", "access_provider": "corp", "access_name": access.name, "findings": []})
        save_access_enrichment(repo, access.id, {"application": "New live value"}, "operator")
        row = projected_rows(str(db), "review_items", limit=10, offset=0, campaign="legacy")["items"][0]
        assert row["manual_context_capture_status"] == "not_captured"
        assert row["business_context"]["manual_context"] == {}
