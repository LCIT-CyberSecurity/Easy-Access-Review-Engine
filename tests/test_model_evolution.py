from __future__ import annotations

from dataclasses import replace

from access_review_engine.domain import (
    SYSTEM_CAPABILITIES,
    Access,
    AccessAssignment,
    AccessRelation,
    AccessRelationType,
    Capability,
    ExpectedAccessModel,
    FunctionalComparisonState,
    FunctionalModelCompleteness,
    FunctionalRight,
    Identity,
    Origin,
    Permission,
    PermissionCapabilityMapping,
    Provenance,
    Target,
    canonical_target_key,
    normalize_manual_target_node,
    target_path,
    target_semantically_equal,
)
from access_review_engine.services import (
    calculate_effective_accesses,
    compare_functional_access_models,
)


def _right(identifier: str, capability: str, *, label: str | None = None) -> FunctionalRight:
    return FunctionalRight(
        Target(resource={"identifier": identifier, "display_name": label or identifier}),
        capability,
    )


def test_identity_and_access_remain_provider_aware_and_keys_are_unchanged() -> None:
    assert (Identity("ldap", "alice", "user", "active").provider, "alice") != (
        Identity("entra", "alice", "user", "active").provider,
        "alice",
    )
    left = Access("Finance", "ldap")
    right = Access("Finance", "crm")
    assert left.key() == "ldap:Finance"
    assert right.key() == "crm:Finance"
    assert left.key() != right.key()


def test_capability_catalogue_is_small_customizable_and_has_no_membership() -> None:
    assert {item.id for item in SYSTEM_CAPABILITIES} == {
        "read",
        "write",
        "delete",
        "execute",
        "approve",
        "admin",
        "grant",
    }
    custom = Capability("sign", "Sign", "Digitally sign a document.")
    assert custom.system is False
    try:
        Capability("membership", "Membership", "Membership mechanism")
    except ValueError:
        pass
    else:
        raise AssertionError("Membership must not be a functional capability")


def test_native_permission_mapping_preserves_native_identifier_and_supports_many_to_one() -> None:
    native = Permission("UPDATE")
    mappings = [
        PermissionCapabilityMapping("postgres", value, ("write",), Provenance.MAPPED)
        for value in ("INSERT", "UPDATE")
    ]
    assert native.identifier == "UPDATE"
    assert [item.capability_ids for item in mappings] == [("write",), ("write",)]
    assert Permission("member").identifier == "member"


def test_target_canonical_identity_ignores_display_name_but_not_identifier() -> None:
    left = Target(resource={"identifier": "salesdb.public.orders", "display_name": "Orders"})
    relabelled = Target(
        resource={"identifier": "salesdb.public.orders", "display_name": "Orders 2026"}
    )
    other = Target(resource={"identifier": "salesdb.public.invoices", "display_name": "Orders"})
    assert canonical_target_key(left) == canonical_target_key(relabelled)
    assert target_semantically_equal(left, relabelled)
    assert not target_semantically_equal(left, other)
    assert target_path(relabelled) == "Orders 2026"


def test_manual_target_normalization_requires_identifier_and_keeps_legacy_readable() -> None:
    try:
        normalize_manual_target_node({"display_name": "No key"})
    except ValueError:
        pass
    else:
        raise AssertionError("manual Target requires a stable identifier")
    assert normalize_manual_target_node({"identifier": "  x ", "display_name": " X "}) == {
        "identifier": "x",
        "display_name": "X",
    }
    historical = Target(resource={"legacyName": "older shape"})
    assert canonical_target_key(historical)


def test_not_defined_does_not_turn_unmapped_rights_into_unexpected() -> None:
    expected = [ExpectedAccessModel("crm", "Legacy", FunctionalModelCompleteness.NOT_DEFINED)]
    observed = [
        ExpectedAccessModel(
            "crm", "Legacy", FunctionalModelCompleteness.COMPLETE, (_right("invoices", "delete"),)
        )
    ]
    rows = compare_functional_access_models(expected, observed)
    assert len(rows) == 1
    assert rows[0]["state"] == FunctionalComparisonState.NOT_DEFINED


def test_partial_additional_right_is_unknown_not_unexpected() -> None:
    expected = [
        ExpectedAccessModel(
            "crm", "Accounting", FunctionalModelCompleteness.PARTIAL, (_right("contacts", "read"),)
        )
    ]
    observed = [
        ExpectedAccessModel(
            "crm",
            "Accounting",
            FunctionalModelCompleteness.PARTIAL,
            (_right("contacts", "read"), _right("invoices", "delete")),
        )
    ]
    rows = compare_functional_access_models(expected, observed)
    states = {row.get("capability_id"): row["state"] for row in rows}
    assert states == {
        "read": FunctionalComparisonState.EXPECTED_AND_OBSERVED,
        "delete": FunctionalComparisonState.UNKNOWN_NOT_ASSERTED,
    }


def test_complete_additional_right_is_unexpected_and_right_key_ignores_labels() -> None:
    expected = [
        ExpectedAccessModel(
            "crm", "Accounting", FunctionalModelCompleteness.COMPLETE, (_right("contacts", "read"),)
        )
    ]
    observed = [
        ExpectedAccessModel(
            "crm",
            "Accounting",
            FunctionalModelCompleteness.COMPLETE,
            (_right("contacts", "read", label="Contact records"), _right("invoices", "delete")),
        )
    ]
    rows = compare_functional_access_models(expected, observed)
    assert [row["state"] for row in rows] == [
        FunctionalComparisonState.EXPECTED_AND_OBSERVED,
        FunctionalComparisonState.UNEXPECTED,
    ]


def test_generic_effective_graph_supports_cross_provider_and_does_not_flatten_assignments() -> None:
    assignment = AccessAssignment(
        "openldap", "GG-CRM-Compta", "entra", "alice", Origin("fixture", True, False)
    )
    relation = AccessRelation(
        "openldap",
        "GG-CRM-Compta",
        "crm",
        "CRM-Compta",
        AccessRelationType.GRANTS,
        Origin("fixture", False, True),
    )
    accesses = [Access("GG-CRM-Compta", "openldap"), Access("CRM-Compta", "crm")]
    result = calculate_effective_accesses([assignment], [relation], accesses)
    assert [row.key() for row in result.effective_accesses] == [
        ("entra", "alice", "crm", "CRM-Compta"),
        ("entra", "alice", "openldap", "GG-CRM-Compta"),
    ]
    assert [assignment.access_name] == ["GG-CRM-Compta"]


def test_comments_and_provenance_are_not_part_of_functional_identity() -> None:
    first = _right("orders", "read")
    second = replace(first, provenance=Provenance.MAPPED, native_permission="SELECT")
    model_a = ExpectedAccessModel(
        "postgres", "analyst", FunctionalModelCompleteness.COMPLETE, (first,)
    )
    model_b = ExpectedAccessModel(
        "postgres", "analyst", FunctionalModelCompleteness.COMPLETE, (second,)
    )
    assert (
        compare_functional_access_models([model_a], [model_b])[0]["state"]
        == FunctionalComparisonState.EXPECTED_AND_OBSERVED
    )
