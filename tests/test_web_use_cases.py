from access_review_engine.domain import (
    Access,
    AccessAssignment,
    Campaign,
    ComparisonState,
    GoldenSourceAssignment,
    Identity,
    IdentityStatus,
    IdentityType,
    Origin,
    Provider,
)
from access_review_engine.services import create_golden_source, create_golden_version, create_snapshot
from access_review_engine.storage import Repository
from access_review_engine.web_use_cases import prepare_campaign_review, snapshot_collection_scope


def test_campaign_comparison_preserves_snapshot_provider_scope(tmp_path):
    db = tmp_path / "scope.db"
    golden = create_golden_version(
        create_golden_source("baseline"),
        [
            GoldenSourceAssignment("corp-ad", "staff", "corp-ad", "alice"),
            GoldenSourceAssignment("salesforce", "sales", "salesforce", "bob"),
            GoldenSourceAssignment("aws", "reader", "aws", "carol"),
        ],
        "manual",
    )
    snapshot = create_snapshot(
        [Provider("corp-ad", "active_directory")],
        [Identity("corp-ad", "alice", IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE)],
        [],
        [Access("staff", "corp-ad")],
        [AccessAssignment("corp-ad", "staff", "corp-ad", "alice", Origin("direct", True, False))],
        ["import-corp"],
    )
    with Repository(db) as repo:
        repo.insert_append_only(
            "imports",
            {
                "id": "import-corp",
                "provider": "corp-ad",
                "completeness": "full",
                "scope": {"type": "providers", "values": ["corp-ad"], "completeness": "full"},
            },
        )
        scope = snapshot_collection_scope(repo, snapshot)

    prepared = prepare_campaign_review(Campaign("Q4", snapshot.id), snapshot, golden, scope)
    classifications = {
        row["access_provider"]: row["classification"] for row in prepared.comparison_states
    }
    assert classifications["corp-ad"] == ComparisonState.EXPECTED_AND_OBSERVED
    assert classifications["salesforce"] == ComparisonState.UNKNOWN_DUE_TO_SCOPE
    assert classifications["aws"] == ComparisonState.UNKNOWN_DUE_TO_SCOPE
    assert ComparisonState.MISSING not in set(classifications.values())


def test_provider_campaign_scope_requires_at_least_one_provider():
    snapshot = create_snapshot([], [], [], [], [], [])
    campaign = Campaign("Empty scope", snapshot.id, scope={"type": "providers", "values": []})

    try:
        prepare_campaign_review(campaign, snapshot, None)
    except ValueError as exc:
        assert "at least one provider" in str(exc)
    else:
        raise AssertionError("An empty provider scope must not open a campaign")


def test_legacy_snapshot_without_import_references_cannot_create_false_missing(tmp_path):
    db = tmp_path / "legacy-scope.db"
    golden = create_golden_version(
        create_golden_source("baseline"),
        [GoldenSourceAssignment("salesforce", "sales", "salesforce", "bob")],
        "manual",
    )
    snapshot = create_snapshot(
        [Provider("corp-ad", "active_directory")],
        [],
        [],
        [],
        [],
        [],
    )
    with Repository(db) as repo:
        scope = snapshot_collection_scope(repo, snapshot)

    prepared = prepare_campaign_review(Campaign("Legacy", snapshot.id), snapshot, golden, scope)

    assert scope == {
        "type": "providers",
        "values": ["corp-ad"],
        "completeness": "unknown",
    }
    assert prepared.comparison_states[0]["classification"] == ComparisonState.UNKNOWN_DUE_TO_SCOPE
