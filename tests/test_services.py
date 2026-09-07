from __future__ import annotations

import pytest

from access_review_engine.domain import (
    Access,
    AccessAssignment,
    Campaign,
    ComparisonState,
    ControlObject,
    DecisionValue,
    Finding,
    GoldenSourceAssignment,
    Identity,
    IdentityStatus,
    IdentityType,
    Origin,
    OwnerRef,
    Permission,
    Provider,
    Target,
)
from access_review_engine.services import (
    close_campaign,
    create_decision,
    create_golden_source,
    create_golden_version,
    create_snapshot,
    golden_diff,
    open_campaign,
    promote_campaign,
    promote_snapshot,
    remediation_from_decisions,
)


def test_comparison_findings_and_scope() -> None:
    owner = Identity("corp-ad", "owner", IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE)
    disabled = Identity("corp-ad", "disabled.user", IdentityType.USER_ACCOUNT, IdentityStatus.DISABLED)
    tech = Identity("corp-ad", "svc.no.owner", IdentityType.TECHNICAL_ACCOUNT, IdentityStatus.ACTIVE)
    access = _access("finance-read", OwnerRef("corp-ad", "owner"))
    observed = [
        AccessAssignment("corp-ad", "finance-read", "corp-ad", "disabled.user", Origin("group", True, False, "GG")),
        AccessAssignment("corp-ad", "finance-read", "corp-ad", "svc.no.owner", Origin("group", True, False, "GG")),
    ]
    golden = create_golden_version(
        create_golden_source("baseline"),
        [
            GoldenSourceAssignment("corp-ad", "finance-read", "corp-ad", "disabled.user"),
            GoldenSourceAssignment("corp-ad", "hr-read", "corp-ad", "missing.user"),
        ],
        "manual_import",
    )

    snapshot = create_snapshot(
        [Provider("corp-ad", "active_directory")],
        [owner, disabled, tech],
        [],
        [access],
        observed,
        ["import-1"],
        golden,
        {"type": "accesses", "values": ["finance-read"]},
    )

    rows = {(r["access_name"], r["identity_identifier"]): r for r in snapshot.comparison_states}
    assert rows[("finance-read", "disabled.user")]["classification"] == ComparisonState.EXPECTED_AND_OBSERVED
    assert Finding.DISABLED_WITH_ACCESS in rows[("finance-read", "disabled.user")]["findings"]
    assert rows[("finance-read", "svc.no.owner")]["classification"] == ComparisonState.UNEXPECTED
    assert Finding.TECHNICAL_ACCOUNT_WITHOUT_OWNER in rows[("finance-read", "svc.no.owner")]["findings"]
    assert rows[("hr-read", "missing.user")]["classification"] == ComparisonState.UNKNOWN_DUE_TO_SCOPE


def test_no_reference_never_marks_unauthorized() -> None:
    identity = Identity("corp-ad", "jean.dupont", IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE)
    access = _access("crm")
    assignment = AccessAssignment("corp-ad", "crm", "corp-ad", "jean.dupont", Origin("group", True, False))
    snapshot = create_snapshot([], [identity], [], [access], [assignment], ["import-1"])
    assert snapshot.comparison_states[0]["classification"] == ComparisonState.NO_REFERENCE


def test_same_login_different_providers_no_collision() -> None:
    corp = Identity("corp-ad", "jean.dupont", IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE)
    europe = Identity("europe-ad", "jean.dupont", IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE)
    assert corp.ref().key() != europe.ref().key()


def test_multiple_origins_same_access_identity_are_preserved() -> None:
    identity = Identity("corp-ad", "jean.dupont", IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE)
    access = _access("finance")
    assignments = [
        AccessAssignment("corp-ad", "finance", "corp-ad", "jean.dupont", Origin("direct", True, False, "direct")),
        AccessAssignment("corp-ad", "finance", "corp-ad", "jean.dupont", Origin("group", True, False, "GG")),
    ]
    snapshot = create_snapshot([], [identity], [], [access], assignments, ["import-1"])
    assert len(snapshot.access_assignments) == 2
    assert assignments[0].origin_fingerprint != assignments[1].origin_fingerprint


def test_golden_source_promote_diff_and_campaign_rules() -> None:
    owner = OwnerRef("corp-ad", "owner")
    owner_identity = Identity("corp-ad", "owner", IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE)
    user = Identity("corp-ad", "paul", IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE)
    access = _access("crm", owner)
    assignment = AccessAssignment("corp-ad", "crm", "corp-ad", "paul", Origin("group", True, False))
    snapshot = create_snapshot([], [owner_identity, user], [], [access], [assignment], ["import-1"])
    golden = create_golden_source("corp")
    v1 = promote_snapshot(golden, snapshot)
    assert v1.version == 1
    assert len(v1.assignments) == 1

    campaign = Campaign("q1", snapshot.id, manager=owner)
    opened, items = open_campaign(campaign, snapshot)
    decision = create_decision(items[0], DecisionValue.REVOKE, "not needed", "owner")
    close_campaign(opened, items, [decision])
    v2 = promote_campaign(golden, opened, items, [decision], v1)
    assert v2.version == 2
    assert v1.assignments
    assert not v2.assignments
    assert golden_diff(v1, v2)[0]["status"] == "removed"
    assert remediation_from_decisions(items, [decision])[0].action == "revoke"



def test_golden_diff_uses_stable_keys_and_rejects_stable_mismatch() -> None:
    old = create_golden_version(
        create_golden_source("baseline"),
        [
            GoldenSourceAssignment(
                "corp-ad",
                "Finance:member",
                "corp-ad",
                "user.old",
                access_native_id="SID-G1",
                access_permission="member",
                identity_native_id="SID-U1",
            )
        ],
        "test",
    )
    renamed = create_golden_version(
        create_golden_source("baseline"),
        [
            GoldenSourceAssignment(
                "corp-ad",
                "Finance-Renamed:member",
                "corp-ad",
                "user.new",
                access_native_id="SID-G1",
                access_permission="member",
                identity_native_id="SID-U1",
            )
        ],
        "test",
    )
    recreated = create_golden_version(
        create_golden_source("baseline"),
        [
            GoldenSourceAssignment(
                "corp-ad",
                "Finance:member",
                "corp-ad",
                "user.old",
                access_native_id="SID-G2",
                access_permission="member",
                identity_native_id="SID-U1",
            )
        ],
        "test",
    )

    assert [row["status"] for row in golden_diff(old, renamed)] == ["unchanged"]
    assert sorted(row["status"] for row in golden_diff(old, recreated)) == ["added", "removed"]


def test_promote_snapshot_rejects_incomplete_snapshot() -> None:
    access = _access("finance")
    golden = create_golden_version(
        create_golden_source("baseline"),
        [GoldenSourceAssignment("corp-ad", "finance", "corp-ad", "expected.user")],
        "manual",
    )
    snapshot = create_snapshot(
        [Provider("corp-ad", "active_directory")],
        [],
        [],
        [access],
        [],
        ["import-1"],
        golden,
        {"type": "providers", "values": ["corp-ad"], "completeness": "unknown"},
    )

    try:
        promote_snapshot(create_golden_source("target"), snapshot)
    except ValueError as exc:
        assert "Cannot promote" in str(exc)
    else:
        raise AssertionError("incomplete snapshot was promoted")


def test_create_golden_version_rejects_duplicate_stable_keys() -> None:
    source = create_golden_source("baseline")
    duplicate = GoldenSourceAssignment(
        "corp-ad",
        "Finance:member",
        "corp-ad",
        "jdupont",
        access_native_id="SID-G",
        access_permission="member",
        identity_native_id="SID-U",
    )
    try:
        create_golden_version(source, [duplicate, duplicate], "test")
    except ValueError as exc:
        assert "duplicate stable" in str(exc)
    else:
        raise AssertionError("duplicate stable Golden key was accepted")

def test_campaign_rejects_pending_promotion_and_close() -> None:
    owner = OwnerRef("corp-ad", "owner")
    owner_identity = Identity("corp-ad", "owner", IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE)
    user = Identity("corp-ad", "paul", IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE)
    access = _access("crm", owner)
    assignment = AccessAssignment("corp-ad", "crm", "corp-ad", "paul", Origin("group", True, False))
    snapshot = create_snapshot([], [owner_identity, user], [], [access], [assignment], ["import-1"])
    campaign, items = open_campaign(Campaign("q1", snapshot.id, manager=owner), snapshot)
    with pytest.raises(ValueError):
        close_campaign(campaign, items, [])
    with pytest.raises(ValueError):
        promote_campaign(create_golden_source("corp"), campaign, items, [], None)


def test_decision_comment_requirements() -> None:
    item = _review_item()
    assert create_decision(item, DecisionValue.APPROVE, None, "owner").value == "approve"
    with pytest.raises(ValueError):
        create_decision(item, DecisionValue.REVOKE, None, "owner")
    with pytest.raises(ValueError):
        create_decision(item, DecisionValue.NOT_APPLICABLE, None, "owner")


def _access(name: str, owner: OwnerRef | None = None) -> Access:
    return Access(
        name=name,
        provider="corp-ad",
        control_object=ControlObject("group", f"GG_{name}", description="Native description"),
        permission=Permission("member"),
        target=Target(service={"identifier": "crm", "display_name": "CRM"}),
        access_owner=owner,
        description="Native description",
    )


def _review_item():
    from access_review_engine.domain import ReviewItem

    return ReviewItem(
        campaign_id="c",
        identity_provider="corp-ad",
        identity_identifier="u",
        identity_status="active",
        access_provider="corp-ad",
        access_name="a",
        control_object={},
        permission={},
        target=None,
        description=None,
        origin=None,
        expected=True,
        observed=True,
        classification="expected_and_observed",
        findings=[],
        account_owner=None,
        access_owner=None,
        reviewer=None,
    )
