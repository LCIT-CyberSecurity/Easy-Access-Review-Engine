from __future__ import annotations

import copy


from access_review_engine.application import _reconcile_accesses
from access_review_engine.domain import (
    Access,
    AccessAssignment,
    AccessRelation,
    AccessRelationType,
    ControlObject,
    Origin,
    Permission,
    Target,
)
from access_review_engine.services import calculate_effective_accesses
from access_review_engine.storage import Repository, hydrate_access


def _access(
    name: str,
    *,
    provider: str = "fixture",
    target: Target | None = None,
    permission: Permission | None = None,
    native_id: str | None = None,
) -> Access:
    control_object = (
        ControlObject("entitlement", name, native_id=native_id) if native_id is not None else None
    )
    return Access(
        name=name,
        provider=provider,
        control_object=control_object,
        permission=permission,
        target=target,
    )


def _relation(parent: str, child: str) -> AccessRelation:
    return AccessRelation(
        parent_provider="fixture",
        parent_access_name=parent,
        child_provider="fixture",
        child_access_name=child,
        relation_type=AccessRelationType.GRANTS,
        origin=Origin("fixture", False, True, "model stress fixture"),
    )


def test_opaque_access_is_valid_and_legacy_round_trips(tmp_path) -> None:
    access = _access("CRM-Sales")
    repo = Repository(tmp_path / "model.db")
    try:
        repo.upsert("accesses", access)
        payload = repo.list_payloads("accesses")[0]
        restored = hydrate_access(payload)
    finally:
        repo.close()

    assert restored.key() == "fixture:CRM-Sales"
    assert restored.target is None
    assert restored.permission is None
    assert restored.control_object is None


def test_access_enrichment_null_to_value_and_value_to_null_is_conservative() -> None:
    target = Target(resource={"identifier": "Contacts"})
    enriched = _reconcile_accesses(
        [_access("Contacts:Read")],
        [_access("Contacts:Read", target=target, permission=Permission("read"))],
    )
    assert enriched[0].target == target
    assert enriched[0].permission == Permission("read")

    retained = _reconcile_accesses(enriched, [_access("Contacts:Read")])
    assert retained[0].target == target
    assert retained[0].permission == Permission("read")


def test_access_target_collision_is_explicit() -> None:
    existing = _access(
        "Contacts:Read",
        target=Target(resource={"identifier": "Contacts"}),
        permission=Permission("read"),
    )
    incoming = _access(
        "Contacts:Read",
        target=Target(resource={"identifier": "Invoices"}),
        permission=Permission("read"),
    )
    try:
        _reconcile_accesses([existing], [incoming])
    except ValueError as exc:
        assert "ACCESS_DEFINITION_COLLISION" in str(exc)
    else:
        raise AssertionError("expected ACCESS_DEFINITION_COLLISION")


def test_access_permission_collision_is_explicit() -> None:
    existing = _access(
        "Contacts:Read",
        target=Target(resource={"identifier": "Contacts"}),
        permission=Permission("read"),
    )
    incoming = _access(
        "Contacts:Read",
        target=Target(resource={"identifier": "Contacts"}),
        permission=Permission("write"),
    )
    try:
        _reconcile_accesses([existing], [incoming])
    except ValueError as exc:
        assert "ACCESS_DEFINITION_COLLISION" in str(exc)
    else:
        raise AssertionError("expected ACCESS_DEFINITION_COLLISION")


def test_model_stress_fixtures_preserve_provider_context_and_provenance() -> None:
    providers = ["aws", "azure", "gcp", "entra", "keycloak", "kubernetes", "github"]
    accesses: list[Access] = []
    assignments: list[AccessAssignment] = []
    relations: list[AccessRelation] = []

    for provider in providers:
        role = f"{provider}:reader"
        child = f"{provider}:resource:read"
        accesses.extend(
            [
                _access(role, provider=provider),
                _access(
                    child,
                    provider=provider,
                    target=Target(resource={"identifier": f"{provider}:resource"}),
                    permission=Permission("read"),
                ),
            ]
        )
        assignments.append(
            AccessAssignment(
                provider,
                role,
                provider,
                "alice",
                Origin("fixture", True, False, provider),
            )
        )
        relations.append(
            AccessRelation(
                provider,
                role,
                provider,
                child,
                AccessRelationType.GRANTS,
                Origin("fixture", False, True, provider),
            )
        )

    evaluation = calculate_effective_accesses(assignments, relations, accesses)
    assert len(evaluation.effective_accesses) == len(providers) * 2
    assert all(item.paths for item in evaluation.effective_accesses)
    assert [item.key() for item in evaluation.effective_accesses] == sorted(
        item.key() for item in evaluation.effective_accesses
    )


def test_cycle_diagnostics_are_deterministic() -> None:
    accesses = [_access("A"), _access("B"), _access("C")]
    assignment = AccessAssignment("fixture", "A", "fixture", "alice", Origin("fixture", True, False))
    relations = [_relation("A", "B"), _relation("B", "C"), _relation("C", "A")]

    first = calculate_effective_accesses([assignment], relations, accesses)
    second = calculate_effective_accesses(
        [copy.deepcopy(assignment)],
        [copy.deepcopy(relation) for relation in reversed(relations)],
        list(reversed(accesses)),
    )

    assert first.diagnostics == second.diagnostics
    assert [item.key() for item in first.effective_accesses] == [
        item.key() for item in second.effective_accesses
    ]


def test_access_variants_preserve_optional_target_and_permission() -> None:
    variants = [
        _access("PREMIUM_USER"),
        _access("Contacts", target=Target(resource={"identifier": "Contacts"})),
        _access("Contacts:Read", permission=Permission("read")),
        _access(
            "FinanceBucket:GetObject",
            target=Target(resource={"identifier": "arn:aws:s3:::finance/*"}),
            permission=Permission("s3:GetObject"),
        ),
    ]

    assert variants[0].target is None and variants[0].permission is None
    assert variants[1].target is not None and variants[1].permission is None
    assert variants[2].target is None
    assert variants[2].permission is not None
    assert variants[2].permission.identifier == "read"
    assert variants[3].target is not None
    assert variants[3].target.resource is not None
    assert variants[3].target.resource["identifier"].endswith("finance/*")
    assert variants[3].permission is not None
    assert variants[3].permission.identifier == "s3:GetObject"


def test_access_names_preserve_case_unicode_and_provider_symbols() -> None:
    access = _access(" Finance/Équipe:Read? ", provider="Provider.Case")

    assert access.name == " Finance/Équipe:Read? "
    assert access.provider == "Provider.Case"
    assert access.key() == "Provider.Case: Finance/Équipe:Read? "


def test_self_loop_is_reported_without_duplicate_effective_access() -> None:
    access = _access("A")
    assignment = AccessAssignment("fixture", "A", "fixture", "alice", Origin("fixture", True, False))

    evaluation = calculate_effective_accesses([assignment], [_relation("A", "A")], [access])

    assert [item.key() for item in evaluation.effective_accesses] == [
        ("fixture", "alice", "fixture", "A")
    ]
    assert [item["type"] for item in evaluation.diagnostics] == ["cycle_detected"]
    assert evaluation.diagnostics[0]["access_chain"] == ["fixture:A", "fixture:A"]


def test_path_limit_bounds_multipath_provenance() -> None:
    accesses = [_access(name) for name in ("A", "B", "C", "D")]
    relations = [
        _relation("A", "B"),
        _relation("A", "C"),
        _relation("B", "D"),
        _relation("C", "D"),
    ]
    assignment = AccessAssignment("fixture", "A", "fixture", "alice", Origin("fixture", True, False))

    evaluation = calculate_effective_accesses(
        [assignment], relations, accesses, max_paths_per_access=1
    )

    d = next(item for item in evaluation.effective_accesses if item.access_name == "D")
    assert len(d.paths) == 1
    assert any(item["type"] == "path_limit_reached" for item in evaluation.diagnostics)


def test_unknown_direct_assignment_is_diagnostic_and_not_materialized() -> None:
    assignment = AccessAssignment(
        "fixture", "missing", "fixture", "alice", Origin("fixture", True, False)
    )

    evaluation = calculate_effective_accesses([assignment], [], [_access("known")])

    assert evaluation.effective_accesses == []
    assert evaluation.diagnostics[0]["type"] == "unresolved_direct_assignment"
    assert evaluation.diagnostics[0]["access_name"] == "missing"


def test_duplicate_relation_observation_keeps_one_path() -> None:
    accesses = [_access("A"), _access("B")]
    assignment = AccessAssignment("fixture", "A", "fixture", "alice", Origin("fixture", True, False))
    relation = _relation("A", "B")

    evaluation = calculate_effective_accesses(
        [assignment], [relation, copy.deepcopy(relation)], accesses
    )

    child = next(item for item in evaluation.effective_accesses if item.access_name == "B")
    assert len(child.paths) == 1
    assert not evaluation.diagnostics


def test_same_native_id_in_different_providers_stays_distinct() -> None:
    accesses = [
        _access("view", provider="aws", native_id="shared-role-id"),
        _access("view", provider="gcp", native_id="shared-role-id"),
    ]
    assignments = [
        AccessAssignment("aws", "view", "aws", "alice", Origin("fixture", True, False)),
        AccessAssignment("gcp", "view", "gcp", "alice", Origin("fixture", True, False)),
    ]

    evaluation = calculate_effective_accesses(assignments, [], accesses)

    assert {item.access_provider for item in evaluation.effective_accesses} == {"aws", "gcp"}
