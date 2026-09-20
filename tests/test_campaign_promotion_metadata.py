from __future__ import annotations

from access_review_engine.domain import (
    Access,
    AccessAssignment,
    Campaign,
    CampaignStatus,
    ControlObject,
    Decision,
    DecisionValue,
    GoldenSourceAssignment,
    Identity,
    IdentityStatus,
    IdentityType,
    Origin,
    Permission,
    Provider,
    ReviewItem,
)
from access_review_engine.services import (
    create_golden_source,
    create_golden_version,
    create_snapshot,
    promote_campaign,
)


def test_campaign_promotion_preserves_and_derives_stable_technical_metadata() -> None:
    identity = Identity(
        "corp-ad",
        "alice",
        IdentityType.USER_ACCOUNT,
        IdentityStatus.ACTIVE,
        native_id="SID-U1",
    )
    access = Access(
        "GG_SAGE_RW:member",
        "corp-ad",
        ControlObject("group", "GG_SAGE_RW", native_id="SID-G1"),
        Permission("member"),
        metadata={
            "eare_business_context": {
                "business_permission": {
                    "value": "ReadWrite",
                    "provenance": "source_attribute",
                    "attribute": "extensionAttribute6",
                }
            }
        },
    )
    snapshot = create_snapshot(
        [Provider("corp-ad", "active_directory")],
        [identity],
        [],
        [access],
        [AccessAssignment("corp-ad", access.name, "corp-ad", "alice", Origin("group", True, False))],
        ["import-1"],
    )
    source = create_golden_source("main")
    previous_assignment = GoldenSourceAssignment(
        "corp-ad",
        access.name,
        "corp-ad",
        "alice",
        access_native_id="SID-G1",
        access_permission="member",
        identity_native_id="SID-U1",
    )
    previous = create_golden_version(source, [previous_assignment], "snapshot")
    campaign = Campaign("campaign", snapshot.id, status=CampaignStatus.CLOSED)
    item = ReviewItem(
        campaign_id=campaign.id,
        identity_provider="corp-ad",
        identity_identifier="alice",
        identity_status=IdentityStatus.ACTIVE,
        access_provider="corp-ad",
        access_name=access.name,
        control_object={"native_id": "SID-G1"},
        permission={"identifier": "member"},
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
    decision = Decision(item.id, DecisionValue.APPROVE, "still required", "reviewer")

    promoted = promote_campaign(
        source,
        campaign,
        [item],
        [decision],
        previous,
        observed_snapshot=snapshot,
    )
    assignment = promoted.assignments[0]
    assert assignment.access_native_id == "SID-G1"
    assert assignment.identity_native_id == "SID-U1"
    assert assignment.access_permission == "member"
    assert assignment.stable_key() == previous_assignment.stable_key()
    assert assignment.access_permission != "ReadWrite"


def test_campaign_promotion_does_not_invent_missing_native_ids_or_permission() -> None:
    source = create_golden_source("main")
    campaign = Campaign("campaign", "snapshot", status=CampaignStatus.CLOSED)
    item = ReviewItem(
        campaign_id=campaign.id,
        identity_provider="legacy",
        identity_identifier="alice",
        identity_status=IdentityStatus.ACTIVE,
        access_provider="legacy",
        access_name="access",
        control_object={},
        permission={},
        target=None,
        description=None,
        origin=None,
        expected=False,
        observed=True,
        classification="unexpected",
        findings=[],
        account_owner=None,
        access_owner=None,
        reviewer=None,
    )
    decision = Decision(item.id, DecisionValue.APPROVE, None, "reviewer")
    promoted = promote_campaign(source, campaign, [item], [decision], None)
    assignment = promoted.assignments[0]
    assert assignment.access_native_id is None
    assert assignment.identity_native_id is None
    assert assignment.access_permission is None
