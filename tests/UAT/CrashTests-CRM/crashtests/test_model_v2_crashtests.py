from access_review_engine.domain import (
    Access,
    AccessAssignment,
    AccessRelation,
    AccessRelationType,
    ExpectedAccessModel,
    FunctionalModelCompleteness,
    FunctionalRight,
    Origin,
    Target,
)
from access_review_engine.services import (
    calculate_effective_accesses,
    compare_functional_access_models,
)


def test_ct_crm_036_golden_completeness_is_conservative_for_functional_rights() -> None:
    known = FunctionalRight(Target(resource={"identifier": "contacts"}), "read")
    additional = FunctionalRight(Target(resource={"identifier": "invoices"}), "delete")
    for completeness, expected_state in (
        (FunctionalModelCompleteness.NOT_DEFINED, "not_defined"),
        (FunctionalModelCompleteness.PARTIAL, "unknown_not_asserted"),
        (FunctionalModelCompleteness.COMPLETE, "unexpected"),
    ):
        expected = [ExpectedAccessModel("nexabyte-crm", "CRM-Compta", completeness, (known,))]
        observed = [ExpectedAccessModel("nexabyte-crm", "CRM-Compta", completeness, (additional,))]
        rows = compare_functional_access_models(expected, observed)
        if completeness == FunctionalModelCompleteness.NOT_DEFINED:
            assert rows[0]["state"] == expected_state
        else:
            additional_row = next(row for row in rows if row.get("capability_id") == "delete")
            assert additional_row["state"] == expected_state


def test_ct_crm_037_cross_provider_group_to_crm_rights_remain_derived() -> None:
    direct = AccessAssignment(
        "openldap-corp",
        "GG-CRM-Compta",
        "entra",
        "alice",
        Origin("fixture", True, False, "LDAP membership"),
    )
    relation = AccessRelation(
        "openldap-corp",
        "GG-CRM-Compta",
        "nexabyte-crm",
        "CRM-Compta",
        AccessRelationType.GRANTS,
        Origin("fixture", False, True, "manual Golden relation"),
    )
    accesses = [Access("GG-CRM-Compta", "openldap-corp"), Access("CRM-Compta", "nexabyte-crm")]
    effective = calculate_effective_accesses([direct], [relation], accesses)
    assert any(
        item.key() == ("entra", "alice", "nexabyte-crm", "CRM-Compta")
        for item in effective.effective_accesses
    )
    assert direct.access_name == "GG-CRM-Compta"
