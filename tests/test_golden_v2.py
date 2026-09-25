from __future__ import annotations


from access_review_engine.domain import (
    Access,
    AccessRelation,
    AccessRelationType,
    Campaign,
    ControlObject,
    DecisionValue,
    ExpectedAccessModel,
    FunctionalModelCompleteness,
    FunctionalRight,
    GoldenAccessComment,
    GoldenSource,
    GoldenSourceAssignment,
    ReviewItem,
    Target,
    Origin,
)
from access_review_engine.golden_functional import functional_access_rows
from access_review_engine.services import create_decision, create_golden_version, evolve_golden_version, promote_campaign
from access_review_engine.storage import Repository, hydrate_golden_version


def test_golden_v1_is_not_defined_and_v2_round_trips_frozen_rights(tmp_path) -> None:
    source = GoldenSource("functional")
    legacy = hydrate_golden_version(
        {
            "golden_source_id": source.id,
            "version": 1,
            "source_type": "legacy",
            "checksum": "historical",
            "assignments": [],
            "id": "legacy-version",
            "created_at": "historical-time",
        }
    )
    assert legacy.schema_version == 1
    assert legacy.functional_access_models == []

    model = ExpectedAccessModel(
        "openldap-corp",
        "GG-CRM-Compta",
        FunctionalModelCompleteness.PARTIAL,
        (FunctionalRight(Target(resource={"identifier": "invoices"}), "write"),),
    )
    version = create_golden_version(
        source,
        [GoldenSourceAssignment("openldap-corp", "GG-CRM-Compta", "entra", "alice")],
        "manual",
        schema_version=2,
        functional_access_models=[model],
        access_comments=[
            GoldenAccessComment("openldap-corp", "GG-CRM-Compta", "Accounting access")
        ],
    )
    repo = Repository(tmp_path / "golden-v2.db")
    try:
        repo.upsert("golden_source_versions", version)
        payload = repo.get_payload("golden_source_versions", version.id)
        assert payload is not None
    finally:
        repo.close()
    hydrated = hydrate_golden_version(payload)
    assert hydrated.schema_version == 2
    assert hydrated.functional_access_models == [model]
    assert hydrated.access_comments[0].comment == "Accounting access"
    assert hydrated.checksum == version.checksum


def test_campaign_promotion_preserves_golden_v2_context() -> None:
    source = GoldenSource("campaign-v2")
    expected_access = Access(
        name="billing-admin",
        provider="crm",
        control_object=ControlObject("role", "billing-admin"),
        target=Target(resource={"identifier": "billing"}),
    )
    model = ExpectedAccessModel(
        "crm",
        "billing-admin",
        FunctionalModelCompleteness.COMPLETE,
        (FunctionalRight(Target(resource={"identifier": "billing"}), "read"),),
    )
    comment = GoldenAccessComment("crm", "billing-admin", "Reviewed baseline")
    previous = create_golden_version(
        source,
        [GoldenSourceAssignment("crm", "billing-admin", "directory", "alice")],
        "manual",
        schema_version=2,
        expected_access_definitions=[expected_access],
        functional_access_models=[model],
        access_comments=[comment],
    )
    item = ReviewItem(
        campaign_id="campaign-1", identity_provider="directory", identity_identifier="alice",
        identity_status="active", access_provider="crm", access_name="billing-admin",
        control_object={"type": "role", "identifier": "billing-admin"}, permission={},
        target={"resource": {"identifier": "billing"}}, description=None, origin=None,
        expected=True, observed=True, classification="expected_and_observed", findings=[],
        account_owner=None, access_owner=None, reviewer=None,
    )
    campaign = Campaign("campaign-1", "snapshot-1", status="closed", golden_source_version_id=previous.id)
    promoted = promote_campaign(
        source, campaign, [item], [create_decision(item, DecisionValue.APPROVE, None, "pilot")], previous
    )

    assert promoted.schema_version == 2
    assert promoted.expected_access_definitions == [expected_access]
    assert promoted.functional_access_models == [model]
    assert promoted.access_comments == [comment]


def test_evolving_any_golden_v2_mutation_preserves_untouched_fields() -> None:
    source = GoldenSource("evolution-v2")
    definition = Access("parent", "crm", control_object=ControlObject("role", "parent"))
    relation = AccessRelation("crm", "parent", "crm", "child", AccessRelationType.GRANTS, Origin("manual", True, False))
    model = ExpectedAccessModel("crm", "parent", FunctionalModelCompleteness.PARTIAL, (FunctionalRight(Target(service={"identifier": "crm"}), "read"),))
    access_comment = GoldenAccessComment("crm", "parent", "Business meaning")
    active = create_golden_version(
        source,
        [GoldenSourceAssignment("ldap", "alice", "crm", "parent", identity_native_id="alice-native")],
        "manual",
        schema_version=2,
        expected_access_definitions=[definition],
        expected_access_relations=[relation],
        functional_access_models=[model],
        access_comments=[access_comment],
    )
    evolved = evolve_golden_version(
        source,
        active,
        [active],
        assignments=[GoldenSourceAssignment("ldap", "bob", "crm", "parent", identity_native_id="bob-native")],
        comment="Holder changed",
    )
    assert evolved.schema_version == 2
    assert evolved.parent_version_id == active.id
    assert evolved.expected_access_definitions == active.expected_access_definitions
    assert evolved.expected_access_relations == active.expected_access_relations
    assert evolved.functional_access_models == active.functional_access_models
    assert evolved.access_comments == active.access_comments


def test_functional_read_model_separates_direct_and_effective_rights(tmp_path) -> None:
    source = GoldenSource("direct-effective")
    parent = Access("parent", "crm", control_object=ControlObject("role", "parent"))
    child = Access("child", "crm", control_object=ControlObject("role", "child"))
    relation = AccessRelation("crm", "parent", "crm", "child", AccessRelationType.GRANTS, Origin("manual", True, False))
    parent_model = ExpectedAccessModel("crm", "parent", FunctionalModelCompleteness.COMPLETE, (FunctionalRight(Target(service={"identifier": "crm"}), "admin"),))
    child_model = ExpectedAccessModel("crm", "child", FunctionalModelCompleteness.COMPLETE, (FunctionalRight(Target(service={"identifier": "crm"}), "read"),))
    version = create_golden_version(source, [], "manual", schema_version=2, expected_access_definitions=[parent, child], expected_access_relations=[relation], functional_access_models=[parent_model, child_model])
    with Repository(tmp_path / "direct-effective.db") as repo:
        rows = {row["access_name"]: row for row in functional_access_rows(repo, version)}
    assert [row["capability_id"] for row in rows["parent"]["direct_functional_rights"]] == ["admin"]
    assert {row["capability_id"] for row in rows["parent"]["effective_functional_rights"]} == {"admin", "read"}
    assert rows["parent"]["expected_grants"] == [{"access_provider": "crm", "access_name": "child"}]
