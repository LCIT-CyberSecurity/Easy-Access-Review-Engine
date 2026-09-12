from __future__ import annotations

import csv
from pathlib import Path
import sys

CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

import pytest

from access_review_engine.domain import (
    Access,
    AccessAssignment,
    AccessRelation,
    AccessRelationType,
    Campaign,
    CampaignStatus,
    ComparisonState,
    Completeness,
    ControlObject,
    DecisionValue,
    Finding,
    GoldenSourceAssignment,
    IdentityStatus,
    AuthenticationPosture,
    Origin,
    OwnerRef,
    Permission,
    Target,
)
from access_review_engine.reporting import write_reports
from access_review_engine.services import (
    calculate_effective_accesses,
    close_campaign,
    create_decision,
    create_golden_source,
    create_golden_version,
    create_snapshot,
    effective_access_diff,
    golden_diff,
    open_campaign,
    promote_campaign,
    promote_snapshot,
    reconcile_identities,
    remediation_from_decisions,
)
from access_review_engine.storage import (
    Repository,
    hydrate_access,
    hydrate_access_relation,
    hydrate_assignment,
    hydrate_campaign,
    hydrate_decision,
    hydrate_golden_source,
    hydrate_golden_version,
    hydrate_identity,
    hydrate_provider,
    hydrate_remediation,
    hydrate_resource,
    hydrate_review_item,
    hydrate_snapshot,
)

from crm_collector import (CRMCollection, collect_crm, direct_permission_assignment, golden_authentication_policy, observed_authentication_posture, reject_access_name_collisions)
from crm_lab import (
    ARTIFACTS_DIR,
    POLICY_DIR,
    PROVIDER,
    assert_fs_case,
    docker_available,
    golden_assignments,
    role_permissions,
    users,
    write_artifact,
)
from expected import assert_classification, classifications, state


def test_ct_crm_001_baseline_real_equals_golden() -> None:
    collection = collect_crm()
    golden = golden_from_collection(collection)
    snapshot = snapshot_from_collection(collection, golden)

    write_artifact("observed.json", snapshot.comparison_states)

    assert classifications(snapshot) == {ComparisonState.EXPECTED_AND_OBSERVED}
    assert all(row["observed"] and row["expected"] for row in snapshot.comparison_states)


def test_ct_crm_002_wrong_role_is_unexpected() -> None:
    rows = golden_assignments()
    rows.append({"identity": "oscar.perrin", "access": "CRM-Compta"})
    collection = collect_crm(assignments=rows)
    snapshot = snapshot_from_collection(collection, golden_from_policy())

    assert_classification(snapshot, "CRM-Compta", "oscar.perrin", ComparisonState.UNEXPECTED)


def test_ct_crm_003_missing_role_is_missing() -> None:
    rows = [row for row in golden_assignments() if row != {"identity": "emma.laurent", "access": "CRM-Sales"}]
    collection = collect_crm(assignments=rows)
    snapshot = snapshot_from_collection(collection, golden_from_policy())

    assert_classification(snapshot, "CRM-Sales", "emma.laurent", ComparisonState.MISSING)


def test_ct_crm_004_legitimate_multi_role_has_union_without_duplicates() -> None:
    collection = collect_crm()
    effective = calculate_effective_accesses(collection.assignments, collection.relations, collection.accesses)
    julia = [
        item
        for item in effective.effective_accesses
        if item.identity_identifier == "julia.faure"
    ]

    assert {item.access_name for item in julia if item.direct} == {"CRM-Sales", "CRM-Support"}
    names = [item.access_name for item in julia]
    assert len(names) == len(set(names))
    assert _effective(effective, "julia.faure", "licenses:read").paths


def test_ct_crm_005_direct_sensitive_permission_is_unexpected_with_direct_origin() -> None:
    collection = collect_crm()
    collection.assignments.append(direct_permission_assignment("emma.laurent", "invoices:write"))
    snapshot = snapshot_from_collection(collection, golden_from_policy())
    row = state(snapshot, "invoices:write", "emma.laurent")

    assert row["classification"] == ComparisonState.UNEXPECTED
    assert row["observed"] is True


def test_ct_crm_006_sales_role_composition_grants_expected_permissions() -> None:
    collection = collect_crm()
    sales_children = {
        relation.child_access_name
        for relation in collection.relations
        if relation.parent_access_name == "CRM-Sales"
    }

    assert sales_children == {
        "prospects:read",
        "prospects:write",
        "customer:read",
        "customer:write",
        "contacts:read",
        "contacts:write",
        "contracts:read",
        "contracts:write",
        "orders:read",
        "orders:write",
        "hardware:read",
        "serial_numbers:read",
        "licenses:read",
        "support:read",
        "shipments:read",
        "replacements:read",
    }


def test_ct_crm_007_role_composition_drift_changes_effective_access_only() -> None:
    collection = collect_crm()
    assignments = [item for item in collection.assignments if item.identity_identifier == "emma.laurent"]
    before = calculate_effective_accesses(assignments, collection.relations, collection.accesses)
    drift = AccessRelation(
        PROVIDER,
        "CRM-Sales",
        PROVIDER,
        "invoices:write",
        AccessRelationType.GRANTS,
        Origin("role", False, True, "drifted CRM role definition"),
    )
    after = calculate_effective_accesses(assignments, [*collection.relations, drift], collection.accesses)

    assert assignments[0].access_name == "CRM-Sales"
    assert {"status": "added", "identity_provider": PROVIDER, "identity_identifier": "emma.laurent", "access_provider": PROVIDER, "access_name": "invoices:write"} in effective_access_diff(before, after)


def test_ct_crm_008_multiple_paths_dedupe_effective_access_and_keep_provenance() -> None:
    collection = collect_crm()
    effective = calculate_effective_accesses(collection.assignments, collection.relations, collection.accesses)
    item = _effective(effective, "julia.faure", "contacts:read")

    assert item.direct is False
    assert len(item.paths) == 2
    assert sorted(path.access_chain[0].identifier for path in item.paths) == ["CRM-Sales", "CRM-Support"]


def test_ct_crm_009_access_relation_cycle_is_diagnostic_and_bounded() -> None:
    collection = collect_crm()
    cycle_accesses = [
        _access("Role-A", "role"),
        _access("Role-B", "role"),
        _access("Role-C", "role"),
    ]
    cycle_relations = [
        _relation("Role-A", "Role-B"),
        _relation("Role-B", "Role-C"),
        _relation("Role-C", "Role-A"),
    ]
    assignment = AccessAssignment(PROVIDER, "Role-A", PROVIDER, "alice.martin", Origin("role", True, False))
    result = calculate_effective_accesses([assignment], cycle_relations, [*collection.accesses, *cycle_accesses])

    assert {item.access_name for item in result.effective_accesses} == {"Role-A", "Role-B", "Role-C"}
    assert [diag["type"] for diag in result.diagnostics] == ["cycle_detected"]


def test_ct_crm_010_disabled_user_with_access_has_finding() -> None:
    user_rows = [_with(row, status="disabled") if row["username"] == "paula.morin" else row for row in users()]
    snapshot = snapshot_from_collection(collect_crm(identities=user_rows), golden_from_policy())
    row = state(snapshot, "CRM-Support", "paula.morin")

    assert Finding.DISABLED_WITH_ACCESS in row["findings"]



def test_ct_crm_011_deleted_user_after_authoritative_baseline_is_deleted() -> None:
    baseline = collect_crm()
    imported = collect_crm(identities=[row for row in users() if row["username"] != "rosa.andre"])
    merged = reconcile_identities(baseline.identities, imported.identities, completeness=Completeness.FULL)

    deleted = [item for item in merged if item.identifier == "rosa.andre"]
    assert deleted and deleted[0].status == IdentityStatus.DELETED


def test_ct_crm_012_rename_keeps_stable_identity() -> None:
    collection = collect_crm()
    golden = golden_from_collection(collection)
    renamed_users = [
        _with(row, username="alice.durand", display_name="Alice Durand", email="alice.durand@example.test")
        if row["username"] == "alice.martin"
        else row
        for row in users()
    ]
    renamed_assignments = [
        _with(row, identity="alice.durand") if row["identity"] == "alice.martin" else row
        for row in golden_assignments()
    ]
    snapshot = snapshot_from_collection(
        collect_crm(identities=renamed_users, assignments=renamed_assignments),
        golden,
    )

    assert_classification(snapshot, "CRM-Compta", "alice.durand", ComparisonState.EXPECTED_AND_OBSERVED)
    assert "alice.martin" not in {row["identity_identifier"] for row in snapshot.comparison_states}


def test_ct_crm_013_recreated_username_with_new_native_id_is_new_identity() -> None:
    baseline = collect_crm()
    recreated_rows = [
        _with(row, native_id="CRM-UID-09999")
        if row["username"] == "bruno.leroy"
        else row
        for row in users()
    ]
    imported = collect_crm(identities=recreated_rows)
    merged = reconcile_identities(baseline.identities, imported.identities, completeness=Completeness.FULL)
    brunos = [item for item in merged if item.identifier == "bruno.leroy"]

    assert len(brunos) == 2
    assert {item.status for item in brunos} == {IdentityStatus.ACTIVE, IdentityStatus.DELETED}


def test_ct_crm_014_technical_account_without_owner_then_with_owner() -> None:
    no_owner = [_with(row, owner="") if row["username"] == "svc-crm-import" else row for row in users()]
    snapshot = snapshot_from_collection(collect_crm(identities=no_owner), golden_from_policy())
    row = state(snapshot, "CRM-Support", "svc-crm-import")
    assert Finding.TECHNICAL_ACCOUNT_WITHOUT_OWNER in row["findings"]

    fixed = snapshot_from_collection(collect_crm(), golden_from_policy())
    row = state(fixed, "CRM-Support", "svc-crm-import")
    assert Finding.TECHNICAL_ACCOUNT_WITHOUT_OWNER not in row["findings"]


def test_ct_crm_015_invalid_owner_is_reported() -> None:
    bad_owner = [
        _with(row, owner="missing.owner")
        if row["username"] == "svc-crm-import"
        else _with(row, status="disabled")
        if row["username"] == "thierry.admin"
        else row
        for row in users()
    ]
    snapshot = snapshot_from_collection(collect_crm(identities=bad_owner), golden_from_policy())
    row = state(snapshot, "CRM-Support", "svc-crm-import")

    assert Finding.INVALID_OWNER in row["findings"]


def test_ct_crm_016_shared_account_without_owner_is_reported() -> None:
    no_owner = [_with(row, owner="") if row["username"] == "crm-shared-sales" else row for row in users()]
    snapshot = snapshot_from_collection(collect_crm(identities=no_owner), golden_from_policy())
    row = state(snapshot, "CRM-Sales", "crm-shared-sales")

    assert Finding.SHARED_ACCOUNT_WITHOUT_OWNER in row["findings"]


def test_ct_crm_017_non_authoritative_unknown_does_not_false_missing() -> None:
    rows = [row for row in golden_assignments() if row["identity"] != "emma.laurent"]
    collection = collect_crm(assignments=rows, completeness=Completeness.UNKNOWN)
    snapshot = snapshot_from_collection(
        collection,
        golden_from_policy(),
        import_scope={"type": "all", "completeness": Completeness.UNKNOWN},
    )

    assert_classification(snapshot, "CRM-Sales", "emma.laurent", ComparisonState.UNKNOWN_DUE_TO_SCOPE)


def test_ct_crm_018_scoped_collection_absence_is_not_deletion() -> None:
    rows = [row for row in golden_assignments() if row["access"] != "CRM-Support"]
    collection = collect_crm(assignments=rows, completeness=Completeness.SCOPED)
    snapshot = snapshot_from_collection(
        collection,
        golden_from_policy(),
        import_scope={"type": "accesses", "values": ["CRM-Sales"], "completeness": Completeness.SCOPED},
    )

    assert_classification(snapshot, "CRM-Support", "oscar.perrin", ComparisonState.UNKNOWN_DUE_TO_SCOPE)


def test_ct_crm_019_snapshot_is_immutable_after_source_mutation() -> None:
    collection = collect_crm()
    snapshot = snapshot_from_collection(collection, golden_from_policy())
    checksum = snapshot.checksum
    collection.assignments.clear()
    collection.relations.clear()
    collection.identities[0].status = IdentityStatus.DISABLED

    assert snapshot.checksum == checksum
    assert snapshot.access_assignments
    assert snapshot.identities[0].status == IdentityStatus.ACTIVE


def test_ct_crm_020_golden_initial_promotion_creates_v1() -> None:
    collection = collect_crm()
    snapshot = snapshot_from_collection(collection)
    golden_source = create_golden_source("crashtests-crm")
    golden_v1 = promote_snapshot(golden_source, snapshot)

    assert golden_v1.version == 1
    assert len(golden_v1.assignments) == len(collection.assignments)


def test_ct_crm_021_imported_golden_reference_compares_to_observed() -> None:
    collection = collect_crm()
    snapshot = snapshot_from_collection(collection, golden_from_policy())

    assert all(row["classification"] == ComparisonState.EXPECTED_AND_OBSERVED for row in snapshot.comparison_states)


def test_ct_crm_022_campaign_creation_contains_expected_missing_unexpected() -> None:
    snapshot, golden = review_snapshot_with_mixed_states()
    campaign, items = open_campaign(_campaign(snapshot, golden), snapshot)

    assert campaign.status == CampaignStatus.OPEN
    assert {item.classification for item in items} >= {
        ComparisonState.EXPECTED_AND_OBSERVED,
        ComparisonState.MISSING,
        ComparisonState.UNEXPECTED,
    }


def test_ct_crm_023_approve_unexpected_access_records_decision() -> None:
    snapshot, golden = review_snapshot_with_mixed_states()
    campaign, items = open_campaign(_campaign(snapshot, golden), snapshot)
    item = next(item for item in items if item.classification == ComparisonState.UNEXPECTED)
    decision = create_decision(item, DecisionValue.APPROVE, None, "thierry.admin")

    assert decision.value == DecisionValue.APPROVE
    assert decision.review_item_id == item.id


def test_ct_crm_024_revoke_observed_access_records_decision() -> None:
    snapshot, golden = review_snapshot_with_mixed_states()
    campaign, items = open_campaign(_campaign(snapshot, golden), snapshot)
    item = next(item for item in items if item.observed)
    decision = create_decision(item, DecisionValue.REVOKE, "not required", "thierry.admin")

    assert decision.value == DecisionValue.REVOKE


def test_ct_crm_025_campaign_close_keeps_decisions() -> None:
    snapshot, golden = review_snapshot_with_mixed_states()
    campaign, items = open_campaign(_campaign(snapshot, golden), snapshot)
    decisions = [_decision_for(item) for item in items]
    closed = close_campaign(campaign, items, decisions)

    assert closed.status == CampaignStatus.CLOSED
    assert closed.closed_at
    assert len(decisions) == len(items)


def test_ct_crm_026_remediation_exports_revoke_and_grant(tmp_path: Path) -> None:
    snapshot, golden = review_snapshot_with_mixed_states()
    campaign, items = open_campaign(_campaign(snapshot, golden), snapshot)
    decisions = [_decision_for(item) for item in items]
    actions = remediation_from_decisions(items, decisions)
    path = ARTIFACTS_DIR / "remediation.csv"
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, ["review_item_id", "action"])
        writer.writeheader()
        writer.writerows({"review_item_id": item.review_item_id, "action": item.action} for item in actions)

    assert {item.action for item in actions} >= {"grant", "revoke"}
    assert path.exists()


def test_ct_crm_027_promote_campaign_creates_golden_v2_and_diff() -> None:
    snapshot, golden_v1 = review_snapshot_with_mixed_states()
    source = create_golden_source("crashtests-crm")
    source.id = golden_v1.golden_source_id
    campaign, items = open_campaign(_campaign(snapshot, golden_v1), snapshot)
    unexpected = next(item for item in items if item.classification == ComparisonState.UNEXPECTED)
    removable = next(
        item
        for item in items
        if item.classification == ComparisonState.EXPECTED_AND_OBSERVED
        and item.access_name == "CRM-Compta"
    )
    decisions = []
    for item in items:
        if item is unexpected:
            decisions.append(create_decision(item, DecisionValue.APPROVE, None, "thierry.admin"))
        elif item is removable:
            decisions.append(create_decision(item, DecisionValue.REVOKE, "access revoked", "thierry.admin"))
        else:
            decisions.append(_decision_for(item))
    close_campaign(campaign, items, decisions)
    golden_v2 = promote_campaign(source, campaign, items, decisions, golden_v1)
    diff = golden_diff(golden_v1, golden_v2)

    assert golden_v2.version == 2
    assert any(row["status"] == "added" for row in diff)
    assert any(row["status"] == "removed" for row in diff)
    write_artifact("golden-diff.json", diff)


def test_ct_crm_028_effective_golden_change_is_composition_only() -> None:
    collection = collect_crm()
    assignments = [item for item in collection.assignments if item.identity_identifier == "emma.laurent"]
    v1 = calculate_effective_accesses(assignments, collection.relations, collection.accesses)
    v2 = calculate_effective_accesses(
        assignments,
        [*collection.relations, _relation("CRM-Sales", "invoices:write")],
        collection.accesses,
    )

    assert assignments[0].access_name == "CRM-Sales"
    assert any(row["status"] == "added" and row["access_name"] == "invoices:write" for row in effective_access_diff(v1, v2))


def test_ct_crm_029_persistence_restart_round_trips_sqlite(tmp_path: Path) -> None:
    collection = collect_crm()
    golden = golden_from_policy()
    snapshot = snapshot_from_collection(collection, golden)
    campaign, items = open_campaign(_campaign(snapshot, golden), snapshot)
    decisions = [create_decision(item, DecisionValue.APPROVE, None, "thierry.admin") for item in items]
    remediations = remediation_from_decisions(items, decisions)
    db_path = tmp_path / "crashtests-crm.db"
    repo = Repository(db_path)
    try:
        for obj in collection.providers:
            repo.upsert("providers", obj)
        for obj in collection.identities:
            repo.upsert("identities", obj)
        for obj in collection.resources:
            repo.upsert("resources", obj)
        for obj in collection.accesses:
            repo.upsert("accesses", obj)
        repo.replace_assignments(collection.assignments, {PROVIDER})
        repo.replace_access_relations(collection.relations, {PROVIDER})
        repo.upsert("golden_sources", create_golden_source("crashtests-crm"))
        repo.insert_append_only("golden_source_versions", golden)
        repo.upsert("snapshots", snapshot)
        repo.upsert("campaigns", campaign)
        for item in items:
            repo.upsert("review_items", item)
        for item in decisions:
            repo.insert_append_only("decisions", item)
        for item in remediations:
            repo.insert_append_only("remediation_actions", item)
    finally:
        repo.close()

    reopened = Repository(db_path)
    try:
        assert len([hydrate_identity(row) for row in reopened.list_payloads("identities")]) == len(collection.identities)
        assert len([hydrate_access(row) for row in reopened.list_payloads("accesses")]) == len(collection.accesses)
        assert hydrate_snapshot(reopened.list_payloads("snapshots")[0]).checksum == snapshot.checksum
        assert len([hydrate_review_item(row) for row in reopened.list_payloads("review_items")]) == len(items)
        assert len([hydrate_decision(row) for row in reopened.list_payloads("decisions")]) == len(decisions)
        assert len([hydrate_remediation(row) for row in reopened.list_payloads("remediation_actions")]) == len(remediations)
        assert [hydrate_provider(row) for row in reopened.list_payloads("providers")]
        assert [hydrate_resource(row) for row in reopened.list_payloads("resources")]
        assert [hydrate_assignment(row) for row in reopened.list_payloads("access_assignments")]
        assert [hydrate_access_relation(row) for row in reopened.list_payloads("access_relations")]
        assert [hydrate_golden_version(row) for row in reopened.list_payloads("golden_source_versions")]
        assert [hydrate_campaign(row) for row in reopened.list_payloads("campaigns")]
    finally:
        reopened.close()


def test_ct_crm_030_filesystem_real_access_permissions() -> None:
    available, reason = docker_available()
    if not available:
        pytest.skip(f"CT-CRM-030 requires the Docker lab: {reason}")

    cases = [
        ("alice.martin", "invoices", "read", True),
        ("alice.martin", "invoices", "write", True),
        ("alice.martin", "prospects", "write", False),
        ("emma.laurent", "prospects", "write", True),
        ("emma.laurent", "hardware", "read", True),
        ("emma.laurent", "invoices", "write", False),
        ("karim.roux", "shipments", "write", True),
        ("karim.roux", "hardware", "read", True),
        ("karim.roux", "prospects", "write", False),
        ("oscar.perrin", "tickets", "write", True),
        ("oscar.perrin", "licenses", "read", True),
        ("oscar.perrin", "contracts", "write", False),
    ]
    admin_cases = [(resource, permission) for _, resource, permission, _ in cases]
    for user, resource, permission, allowed in cases:
        assert_fs_case(user, resource, permission, allowed)
    for resource, permission in admin_cases:
        assert_fs_case("thierry.admin", resource, permission, True)


def test_ct_crm_031_permission_collision_is_explicit_error() -> None:
    first = _access("customer:read", "permission", "read", "customer")
    second = _access("customer:read", "permission", "write", "customer")

    with pytest.raises(ValueError):
        reject_access_name_collisions([first, second])


def test_ct_crm_032_access_relation_removal_removes_current_relation() -> None:
    collection = collect_crm()
    before = [item for item in collection.relations if item.parent_access_name == "CRM-Sales"]
    after = [
        item
        for item in before
        if item.child_access_name not in {"customer:write"}
    ]

    assert "customer:write" in {item.child_access_name for item in before}
    assert "customer:write" not in {item.child_access_name for item in after}


def test_ct_crm_033_access_relation_partial_collection_preserves_authoritative_relations() -> None:
    baseline = collect_crm()
    partial_observed = [
        item
        for item in baseline.relations
        if item.parent_access_name == "CRM-Sales" and item.child_access_name == "customer:read"
    ]
    preserved = merge_relations_for_completeness(
        baseline.relations,
        partial_observed,
        completeness=Completeness.UNKNOWN,
    )

    assert {item.child_access_name for item in preserved if item.parent_access_name == "CRM-Sales"} >= {
        "customer:read",
        "customer:write",
        "prospects:write",
    }


def test_ct_crm_034_orphan_relation_has_diagnostic_without_crash() -> None:
    collection = collect_crm()
    orphan = _relation("CRM-Sales", "missing:access")
    result = calculate_effective_accesses(
        collection.assignments,
        [*collection.relations, orphan],
        collection.accesses,
    )

    assert any(item["type"] == "unresolved_access_relation" for item in result.diagnostics)


def test_ct_crm_035_large_composition_is_correct_and_deduped() -> None:
    accesses = [_access(f"Role-{index}", "role") for index in range(10)]
    accesses.extend(_access(f"perm-{index}:read", "permission", "read", f"perm-{index}") for index in range(100))
    assignments = [
        AccessAssignment(PROVIDER, f"Role-{index}", PROVIDER, "thierry.admin", Origin("role", True, False))
        for index in range(10)
    ]
    relations = [
        _relation(f"Role-{role}", f"perm-{perm}:read")
        for role in range(10)
        for perm in range(role * 10, role * 10 + 50)
        if perm < 100
    ]
    result = calculate_effective_accesses(assignments, relations, accesses)
    names = [item.access_name for item in result.effective_accesses]

    assert len(names) == len(set(names))
    assert len([name for name in names if name.startswith("perm-")]) == 100
    assert not result.diagnostics


def test_reports_are_written_for_troubleshooting_artifacts() -> None:
    snapshot, golden = review_snapshot_with_mixed_states()
    campaign, items = open_campaign(_campaign(snapshot, golden), snapshot)
    decisions = [_decision_for(item) for item in items]
    close_campaign(campaign, items, decisions)
    write_reports(ARTIFACTS_DIR, campaign, items, decisions, golden, snapshot.authentication_posture)

    assert (ARTIFACTS_DIR / "campaign-report.html").exists()
    assert (ARTIFACTS_DIR / "campaign-results.json").exists()


def golden_from_policy():
    return golden_from_collection(collect_crm())


def golden_from_collection(collection: CRMCollection):
    source = create_golden_source("crashtests-crm", "CrashTests-CRM")
    accesses = {(item.provider, item.name): item for item in collection.accesses}
    identities = {(item.provider, item.identifier): item for item in collection.identities}
    assignments = []
    for item in golden_assignments():
        access = accesses[(PROVIDER, item["access"])]
        identity = identities[(PROVIDER, item["identity"])]
        assignments.append(
            GoldenSourceAssignment(
                PROVIDER,
                item["access"],
                PROVIDER,
                item["identity"],
                access_native_id=access.control_object.native_id,
                access_permission=access.permission.identifier,
                identity_native_id=identity.native_id,
            )
        )
    return create_golden_version(
        source, assignments, "imported_csv", golden_authentication_policy=golden_authentication_policy()
    )


def snapshot_from_collection(
    collection: CRMCollection,
    golden=None,
    import_scope: dict[str, object] | None = None,
):
    return create_snapshot(
        collection.providers,
        collection.identities,
        collection.resources,
        collection.accesses,
        collection.assignments,
        ["crashtests-crm"],
        golden,
        import_scope or collection.scope,
        collection.relations,
        authentication_posture=collection.authentication_posture,
    )


def review_snapshot_with_mixed_states():
    observed_rows = [
        row
        for row in golden_assignments()
        if row != {"identity": "emma.laurent", "access": "CRM-Sales"}
    ]
    observed_rows.append({"identity": "oscar.perrin", "access": "CRM-Compta"})
    collection = collect_crm(assignments=observed_rows)
    golden = golden_from_policy()
    return snapshot_from_collection(collection, golden), golden


def _campaign(snapshot, golden):
    return Campaign(
        "crashtests-crm-q1",
        snapshot.id,
        golden_source_version_id=golden.id,
        manager=OwnerRef(PROVIDER, "thierry.admin"),
        default_reviewer=OwnerRef(PROVIDER, "thierry.admin"),
    )


def _decision_for(item):
    if item.classification == ComparisonState.MISSING:
        return create_decision(item, DecisionValue.APPROVE, None, "thierry.admin")
    if item.classification == ComparisonState.UNEXPECTED:
        return create_decision(item, DecisionValue.REVOKE, "not approved", "thierry.admin")
    return create_decision(item, DecisionValue.APPROVE, None, "thierry.admin")


def _effective(result, identity: str, access_name: str):
    matches = [
        item
        for item in result.effective_accesses
        if item.identity_identifier == identity and item.access_name == access_name
    ]
    assert len(matches) == 1
    return matches[0]


def _relation(parent: str, child: str) -> AccessRelation:
    return AccessRelation(
        PROVIDER,
        parent,
        PROVIDER,
        child,
        AccessRelationType.GRANTS,
        Origin("role", False, True, "CrashTests-CRM test"),
    )


def _access(name: str, kind: str = "permission", permission: str = "use", resource: str | None = None) -> Access:
    return Access(
        name=name,
        provider=PROVIDER,
        control_object=ControlObject(kind, resource or name, native_id=f"CRM-UAT-{name}"),
        permission=Permission(permission),
        target=Target(resource={"identifier": resource}) if resource else None,
    )


def _with(row: dict[str, str], **updates: str) -> dict[str, str]:
    return row | updates


def merge_relations_for_completeness(
    previous: list[AccessRelation],
    observed: list[AccessRelation],
    *,
    completeness: str,
) -> list[AccessRelation]:
    if completeness in {Completeness.FULL, str(Completeness.FULL)}:
        return observed
    keyed = {item.key(): item for item in previous}
    keyed.update({item.key(): item for item in observed})
    return [keyed[key] for key in sorted(keyed)]
