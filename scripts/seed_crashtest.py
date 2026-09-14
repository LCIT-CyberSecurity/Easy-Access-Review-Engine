from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
CRASHTESTS = ROOT / "tests" / "UAT" / "CrashTests-CRM" / "crashtests"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(CRASHTESTS))

from access_review_engine.domain import Campaign, Completeness, ImportBatch, OwnerRef, stable_checksum
from access_review_engine.services import create_golden_source, create_golden_version, create_snapshot, open_campaign
from access_review_engine.storage import Repository
from crm_collector import collect_crm
from crm_lab import PROVIDER, golden_assignments
from crm_collector import golden_authentication_policy


def seed(db_path: str | Path) -> dict[str, int | str]:
    collection = collect_crm()
    golden_source = create_golden_source("crashtests-crm", "CrashTests CRM")
    access_by_key = {(item.provider, item.name): item for item in collection.accesses}
    identity_by_key = {(item.provider, item.identifier): item for item in collection.identities}
    from access_review_engine.domain import GoldenSourceAssignment

    golden_items = [
        GoldenSourceAssignment(
            access_provider=PROVIDER,
            access_name=row["access"],
            identity_provider=PROVIDER,
            identity_identifier=row["identity"],
            access_native_id=access_by_key[(PROVIDER, row["access"])].control_object.native_id,
            access_permission=access_by_key[(PROVIDER, row["access"])].permission.identifier,
            identity_native_id=identity_by_key[(PROVIDER, row["identity"])].native_id,
        )
        for row in golden_assignments()
    ]
    golden_version = create_golden_version(
        golden_source,
        golden_items,
        "imported_crashtest_policy",
        golden_authentication_policy=golden_authentication_policy(),
    )
    golden_source.active_version_id = golden_version.id
    import_batch = ImportBatch(
        provider=PROVIDER,
        source_type="crashtests-crm",
        status="completed",
        completeness=str(Completeness.FULL),
        scope={"type": "providers", "values": [PROVIDER], "completeness": str(Completeness.FULL)},
        checksum=stable_checksum({"source": "CrashTests-CRM", "users": len(collection.identities), "assignments": len(collection.assignments)}),
        completed_at=datetime.now(UTC).isoformat(),
    )
    snapshot = create_snapshot(
        collection.providers,
        collection.identities,
        collection.resources,
        collection.accesses,
        collection.assignments,
        [import_batch.id],
        golden_version,
        collection.scope,
        collection.relations,
        authentication_posture=collection.authentication_posture,
    )
    campaign = Campaign(
        "crashtests-crm-review",
        snapshot.id,
        display_name="CrashTests CRM access review",
        golden_source_version_id=golden_version.id,
        manager=OwnerRef(PROVIDER, "thierry.admin"),
        default_reviewer=OwnerRef(PROVIDER, "thierry.admin"),
    )
    campaign, review_items = open_campaign(campaign, snapshot)
    repo = Repository(db_path)
    try:
        with repo.transaction():
            repo.upsert("imports", import_batch)
            for item in collection.providers:
                repo.upsert("providers", item)
            for item in collection.identities:
                repo.upsert("identities", item)
            for item in collection.resources:
                repo.upsert("resources", item)
            for item in collection.accesses:
                repo.upsert("accesses", item)
            for item in collection.assignments:
                repo.upsert("access_assignments", item)
            for item in collection.relations:
                repo.upsert("access_relations", item)
            repo.upsert("golden_sources", golden_source)
            repo.upsert("golden_source_versions", golden_version)
            repo.insert_append_only("snapshots", snapshot)
            repo.upsert("campaigns", campaign)
            for item in review_items:
                repo.upsert("review_items", item)
    finally:
        repo.close()
    return {"provider": PROVIDER, "identities": len(collection.identities), "accesses": len(collection.accesses), "assignments": len(collection.assignments), "review_items": len(review_items), "snapshot_id": snapshot.id}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Seed the CrashTests-CRM dataset into an EARE SQLite database")
    parser.add_argument("db", nargs="?", default="integration.db")
    args = parser.parse_args()
    print(seed(args.db))
