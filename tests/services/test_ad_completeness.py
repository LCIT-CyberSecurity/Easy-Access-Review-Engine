from __future__ import annotations

from access_review_engine.domain import (
    Access,
    AccessAssignment,
    ControlObject,
    Finding,
    GoldenSourceAssignment,
    Identity,
    IdentityStatus,
    IdentityType,
    Origin,
    Permission,
)
from access_review_engine.services import create_golden_source, create_golden_version, create_snapshot


def test_unknown_collection_cannot_produce_missing() -> None:
    access = Access("finance", "corp-ad", ControlObject("group", "GG_FINANCE"), Permission("member"))
    golden = create_golden_version(
        create_golden_source("baseline"),
        [GoldenSourceAssignment("corp-ad", "finance", "corp-ad", "expected.user")],
        "manual_import",
    )
    snapshot = create_snapshot([], [], [], [access], [], ["import-1"], golden, {"type": "all", "completeness": "unknown"})
    assert snapshot.comparison_states[0]["classification"] == "unknown_due_to_scope"
    assert Finding.COLLECTION_INCOMPLETE in snapshot.comparison_states[0]["findings"]


def test_unknown_enabled_identity_with_access_is_not_reported_disabled() -> None:
    identity = Identity(
        "corp-ad",
        "enabled.unknown",
        IdentityType.USER_ACCOUNT,
        IdentityStatus.UNKNOWN,
    )
    access = Access("finance", "corp-ad", ControlObject("group", "GG_FINANCE"), Permission("member"))
    assignment = AccessAssignment("corp-ad", "finance", "corp-ad", "enabled.unknown", Origin("group", True, False))
    snapshot = create_snapshot([], [identity], [], [access], [assignment], ["import-1"])
    findings = snapshot.comparison_states[0]["findings"]
    assert Finding.DISABLED_WITH_ACCESS not in findings
    assert Finding.UNKNOWN_IDENTITY in findings


def test_ad_account_findings_are_distinct_and_cumulative() -> None:
    identity = Identity(
        "corp-ad",
        "locked.expired",
        IdentityType.USER_ACCOUNT,
        IdentityStatus.ACTIVE,
        metadata={"locked_out": True, "account_expiration_date": "2020-01-01T00:00:00"},
    )
    access = Access("finance", "corp-ad", ControlObject("group", "GG_FINANCE"), Permission("member"))
    assignment = AccessAssignment("corp-ad", "finance", "corp-ad", "locked.expired", Origin("group", True, False))
    snapshot = create_snapshot([], [identity], [], [access], [assignment], ["import-1"])
    findings = snapshot.comparison_states[0]["findings"]
    assert Finding.ACCOUNT_LOCKED in findings
    assert Finding.ACCOUNT_EXPIRED in findings
    assert Finding.DISABLED_WITH_ACCESS not in findings
