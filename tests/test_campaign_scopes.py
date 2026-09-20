from __future__ import annotations

import pytest

from access_review_engine.campaign_authorization import (
    CampaignScopeError,
    campaign_authorization_providers,
    can_access_campaign,
    normalize_campaign_scope,
)
from access_review_engine.domain import (
    Access,
    AccessAssignment,
    Campaign,
    GoldenSourceAssignment,
    Identity,
    IdentityStatus,
    IdentityType,
    Origin,
    Provider,
)
from access_review_engine.services import create_golden_source, create_golden_version, create_snapshot
from access_review_engine.web_use_cases import prepare_campaign_review


def test_campaign_scope_normalization_validates_access_business_keys() -> None:
    assert normalize_campaign_scope({"type": "all"}) == {"type": "all"}
    assert normalize_campaign_scope({"type": "providers", "values": [" ad-france "]}) == {
        "type": "providers",
        "values": ["ad-france"],
    }
    assert normalize_campaign_scope(
        {"type": "accesses", "values": [{"provider": "ad-corp", "name": " GG_SAGE_RW "}]}
    ) == {"type": "accesses", "values": [{"provider": "ad-corp", "name": "GG_SAGE_RW"}]}

    for invalid in (
        {"type": "accesses"},
        {"type": "accesses", "values": []},
        {"type": "accesses", "values": [{"provider": "ad-corp"}]},
        {"type": "accesses", "values": [{"provider": "", "name": "staff"}]},
        {"type": "accesses", "values": [{"provider": "ad-corp", "name": "staff"}, {"provider": "ad-corp", "name": " staff "}]},
        {"type": "invalid", "values": []},
        {"type": "providers", "values": []},
    ):
        with pytest.raises(CampaignScopeError):
            normalize_campaign_scope(invalid)


def _comparison_fixture():
    identities = [
        Identity("openldap-corp", name, IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE)
        for name in ("alice", "bob", "carol", "dave")
    ]
    accesses = [Access(name, "ad-corp") for name in ("GG_SAGE_RW", "GG_SAGE_RO", "GG_SAGE_ADMIN", "GG_OTHER")]
    assignments = [
        AccessAssignment("ad-corp", name, "openldap-corp", identity.identifier, Origin("direct", True, False))
        for name, identity in zip(("GG_SAGE_RW", "GG_SAGE_RO", "GG_SAGE_ADMIN", "GG_OTHER"), identities)
    ]
    snapshot = create_snapshot(
        [Provider("ad-corp", "active_directory"), Provider("openldap-corp", "openldap")],
        identities,
        [],
        accesses,
        assignments,
        ["import-ad", "import-ldap"],
    )
    golden = create_golden_version(
        create_golden_source("main"),
        [
            GoldenSourceAssignment("ad-corp", "GG_SAGE_RW", "openldap-corp", "alice"),
            GoldenSourceAssignment("ad-corp", "GG_SAGE_RO", "openldap-corp", "bob"),
            GoldenSourceAssignment("ad-corp", "GG_SAGE_MISSING", "openldap-corp", "carol"),
        ],
        "manual",
    )
    return snapshot, golden


def test_access_scope_filters_all_comparison_states_by_provider_and_name() -> None:
    snapshot, golden = _comparison_fixture()
    campaign = Campaign(
        "Sage only",
        snapshot.id,
        scope={
            "type": "accesses",
            "values": [
                {"provider": "ad-corp", "name": "GG_SAGE_RW"},
                {"provider": "ad-corp", "name": "GG_SAGE_RO"},
                {"provider": "ad-corp", "name": "GG_SAGE_MISSING"},
            ],
        },
    )
    prepared = prepare_campaign_review(campaign, snapshot, golden)
    assert {(row["access_provider"], row["access_name"]) for row in prepared.comparison_states} == {
        ("ad-corp", "GG_SAGE_RW"),
        ("ad-corp", "GG_SAGE_RO"),
        ("ad-corp", "GG_SAGE_MISSING"),
    }
    classifications = {row["access_name"]: row["classification"] for row in prepared.comparison_states}
    assert classifications["GG_SAGE_RW"] == "expected_and_observed"
    assert classifications["GG_SAGE_RO"] == "expected_and_observed"
    assert classifications["GG_SAGE_MISSING"] == "missing"
    assert "GG_SAGE_ADMIN" not in classifications
    assert "GG_OTHER" not in classifications


def test_access_scope_can_include_unexpected_and_unknown_rows_and_no_reference() -> None:
    snapshot, golden = _comparison_fixture()
    scope = {"type": "accesses", "values": [{"provider": "ad-corp", "name": "GG_SAGE_ADMIN"}]}
    unexpected = prepare_campaign_review(Campaign("Unexpected", snapshot.id, scope=scope), snapshot, golden)
    assert [row["classification"] for row in unexpected.comparison_states] == ["unexpected"]

    unknown = prepare_campaign_review(
        Campaign("Unknown", snapshot.id, scope=scope),
        snapshot,
        golden,
        {"type": "providers", "values": ["openldap-corp"], "completeness": "unknown"},
    )
    # Existing compare semantics leave observed-but-unexpected rows unexpected; a selected
    # Golden-only row outside collection coverage is represented as unknown due to scope.
    missing_scope = {"type": "accesses", "values": [{"provider": "ad-corp", "name": "GG_SAGE_MISSING"}]}
    unknown_missing = prepare_campaign_review(
        Campaign("Unknown missing", snapshot.id, scope=missing_scope),
        snapshot,
        golden,
        {"type": "providers", "values": ["openldap-corp"], "completeness": "unknown"},
    )
    assert unknown_missing.comparison_states[0]["classification"] == "unknown_due_to_scope"

    no_reference = prepare_campaign_review(Campaign("No Golden", snapshot.id, scope=scope), snapshot, None)
    assert no_reference.comparison_states[0]["classification"] == "no_reference"
    assert unknown.comparison_states[0]["access_name"] == "GG_SAGE_ADMIN"


def test_access_scope_rejects_unknown_context_without_creating_accesses() -> None:
    snapshot, golden = _comparison_fixture()
    before = [(access.provider, access.name) for access in snapshot.accesses]
    campaign = Campaign(
        "Bad reference",
        snapshot.id,
        scope={"type": "accesses", "values": [{"provider": "ad-corp", "name": "GG_DOES_NOT_EXIST"}]},
    )
    try:
        prepare_campaign_review(campaign, snapshot, golden)
    except ValueError as exc:
        assert "not found" in str(exc)
    else:
        raise AssertionError("An unknown Access reference must be rejected")
    assert [(access.provider, access.name) for access in snapshot.accesses] == before


def test_campaign_authorization_includes_access_and_identity_providers() -> None:
    scope = {"type": "accesses", "values": [{"provider": "crm", "name": "reader"}]}
    providers = campaign_authorization_providers(
        scope,
        [{"access_provider": "crm", "identity_provider": "openldap-corp"}],
    )
    assert providers == {"crm", "openldap-corp"}
    assert can_access_campaign("OPERATOR", ["crm"], providers) is False
    assert can_access_campaign("OPERATOR", ["crm", "openldap-corp"], providers) is True
    assert can_access_campaign("OPERATOR", ["*"], providers) is True
    assert can_access_campaign("ADMIN", [], providers) is True
    assert can_access_campaign("GROUP_OWNER", ["*"], providers) is False
    assert can_access_campaign("BUSINESS_ADMIN", ["crm"], providers) is False


def test_explicit_scope_stays_authorized_when_comparison_has_no_rows() -> None:
    providers = campaign_authorization_providers(
        {"type": "providers", "values": ["ad-germany"]},
        [],
    )
    assert providers == {"ad-germany"}
    assert not can_access_campaign("OPERATOR", ["ad-france"], providers)
