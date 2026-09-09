from __future__ import annotations

from access_review_engine.domain import (
    Access,
    AccessAssignment,
    AccessRelation,
    AccessRelationType,
    ControlObject,
    Identity,
    IdentityStatus,
    IdentityType,
    Origin,
    Permission,
    Target,
)
from access_review_engine.services import calculate_effective_accesses, effective_access_diff


def test_simple_access_relation_grants_child_access() -> None:
    accesses = [_access("A"), _access("B")]
    assignment = _assignment("bob", "A")
    relation = _relation("A", "B", source="RBAC role definition")

    evaluation = calculate_effective_accesses([assignment], [relation], accesses)

    assert _effective_names(evaluation) == ["A", "B"]
    assert _effective(evaluation, "B").paths[0].access_chain[-1].identifier == "B"
    assert not evaluation.diagnostics


def test_multi_level_access_relation_resolution() -> None:
    accesses = [_access("A"), _access("B"), _access("C")]
    evaluation = calculate_effective_accesses(
        [_assignment("bob", "A")],
        [_relation("A", "B"), _relation("B", "C")],
        accesses,
    )

    c = _effective(evaluation, "C")
    assert _effective_names(evaluation) == ["A", "B", "C"]
    assert [step.identifier for step in c.paths[0].access_chain] == ["A", "B", "C"]


def test_cycle_is_reported_and_traversal_stays_bounded() -> None:
    accesses = [_access("A"), _access("B"), _access("C")]
    evaluation = calculate_effective_accesses(
        [_assignment("bob", "A")],
        [_relation("A", "B"), _relation("B", "C"), _relation("C", "A")],
        accesses,
    )

    assert _effective_names(evaluation) == ["A", "B", "C"]
    assert [item["type"] for item in evaluation.diagnostics] == ["cycle_detected"]
    assert evaluation.diagnostics[0]["access_chain"] == ["app:A", "app:B", "app:C", "app:A"]


def test_multiple_paths_dedupe_effective_access_and_preserve_provenance() -> None:
    accesses = [_access("A"), _access("B"), _access("C")]
    evaluation = calculate_effective_accesses(
        [_assignment("bob", "A"), _assignment("bob", "B")],
        [_relation("A", "C"), _relation("B", "C")],
        accesses,
    )

    c = _effective(evaluation, "C")
    assert _effective_names(evaluation) == ["A", "B", "C"]
    assert c.direct is False
    assert sorted(
        [step.identifier for step in path.access_chain] for path in c.paths
    ) == [["A", "C"], ["B", "C"]]


def test_same_resource_with_different_permissions_remains_distinct() -> None:
    read = _access("customers:read", permission="read", resource="customers")
    write = _access("customers:write", permission="write", resource="customers")

    assert read.name != write.name
    assert read.permission.identifier != write.permission.identifier
    assert {access.name for access in [read, write]} == {"customers:read", "customers:write"}


def test_orphan_relation_is_reported_and_not_materialized() -> None:
    evaluation = calculate_effective_accesses(
        [_assignment("bob", "A")],
        [_relation("A", "missing")],
        [_access("A")],
    )

    assert _effective_names(evaluation) == ["A"]
    assert evaluation.diagnostics[0]["type"] == "unresolved_access_relation"
    assert evaluation.diagnostics[0]["missing"] == ["child_access"]


def test_rbac_role_is_modeled_as_access_granting_permissions() -> None:
    accesses = [
        _access("Sales-Manager", kind="role"),
        _access("customers:read", permission="read", resource="customers"),
        _access("customers:write", permission="write", resource="customers"),
        _access("customers:export", permission="export", resource="customers"),
        _access("reports:read", permission="read", resource="reports"),
    ]

    evaluation = calculate_effective_accesses(
        [_assignment("Bob", "Sales-Manager")],
        [
            _relation("Sales-Manager", "customers:read", source="CRM role definition"),
            _relation("Sales-Manager", "customers:write", source="CRM role definition"),
            _relation("Sales-Manager", "customers:export", source="CRM role definition"),
            _relation("Sales-Manager", "reports:read", source="CRM role definition"),
        ],
        accesses,
    )

    assert _effective_names(evaluation) == [
        "Sales-Manager",
        "customers:export",
        "customers:read",
        "customers:write",
        "reports:read",
    ]


def test_active_directory_nested_group_can_distinguish_direct_and_effective_membership() -> None:
    accesses = [
        _access("GG_FINANCE:member", kind="group"),
        _access("GG_ERP_USERS:member", kind="group"),
    ]
    evaluation = calculate_effective_accesses(
        [_assignment("Bob", "GG_FINANCE:member", source="direct membership")],
        [_relation("GG_FINANCE:member", "GG_ERP_USERS:member", source="AD nested group")],
        accesses,
    )

    assert _effective(evaluation, "GG_FINANCE:member").direct is True
    assert _effective(evaluation, "GG_ERP_USERS:member").direct is False


def test_aws_role_grants_are_generic_access_relations() -> None:
    accesses = [
        _access("FinanceManagerRole", kind="role"),
        _access(
            "bucket-finance:s3:GetObject",
            permission="s3:GetObject",
            resource="bucket-finance",
        ),
        _access(
            "bucket-finance:s3:PutObject",
            permission="s3:PutObject",
            resource="bucket-finance",
        ),
        _access("key-finance:kms:Decrypt", permission="kms:Decrypt", resource="key-finance"),
    ]
    evaluation = calculate_effective_accesses(
        [_assignment("Alice", "FinanceManagerRole")],
        [
            _relation(
                "FinanceManagerRole",
                "bucket-finance:s3:GetObject",
                source="AWS role policy",
            ),
            _relation(
                "FinanceManagerRole",
                "bucket-finance:s3:PutObject",
                source="AWS role policy",
            ),
            _relation("FinanceManagerRole", "key-finance:kms:Decrypt", source="AWS role policy"),
        ],
        accesses,
    )

    assert "bucket-finance:s3:PutObject" in _effective_names(evaluation)
    assert "key-finance:kms:Decrypt" in _effective_names(evaluation)


def test_database_role_grants_table_permissions() -> None:
    accesses = [
        _access("DB Role: analyst", kind="database_role"),
        _access("table-orders:SELECT", permission="SELECT", resource="table-orders"),
        _access("table-customers:SELECT", permission="SELECT", resource="table-customers"),
    ]
    evaluation = calculate_effective_accesses(
        [_assignment("Alice", "DB Role: analyst")],
        [
            _relation(
                "DB Role: analyst",
                "table-orders:SELECT",
                source="database role inheritance",
            ),
            _relation(
                "DB Role: analyst",
                "table-customers:SELECT",
                source="database role inheritance",
            ),
        ],
        accesses,
    )

    assert _effective_names(evaluation) == [
        "DB Role: analyst",
        "table-customers:SELECT",
        "table-orders:SELECT",
    ]


def test_linux_group_grants_sudo_access() -> None:
    accesses = [
        _access("linux-group:ops", kind="linux_group"),
        _access("server01:sudo", permission="sudo", resource="server01"),
    ]
    evaluation = calculate_effective_accesses(
        [_assignment("Bob", "linux-group:ops")],
        [_relation("linux-group:ops", "server01:sudo", source="Linux group/sudo mapping")],
        accesses,
    )

    assert _effective_names(evaluation) == ["linux-group:ops", "server01:sudo"]


def test_role_composition_change_diff_exposes_effective_access_delta() -> None:
    accesses = [
        _access("Sales-Manager", kind="role"),
        _access("customers:read", permission="read", resource="customers"),
        _access("customers:write", permission="write", resource="customers"),
        _access("customers:delete", permission="delete", resource="customers"),
    ]
    assignment = _assignment("Bob", "Sales-Manager")
    v1 = calculate_effective_accesses(
        [assignment],
        [
            _relation("Sales-Manager", "customers:read"),
            _relation("Sales-Manager", "customers:write"),
        ],
        accesses,
    )
    v2 = calculate_effective_accesses(
        [assignment],
        [
            _relation("Sales-Manager", "customers:read"),
            _relation("Sales-Manager", "customers:write"),
            _relation("Sales-Manager", "customers:delete"),
        ],
        accesses,
    )

    assert [row for row in effective_access_diff(v1, v2) if row["status"] == "added"] == [
        {
            "status": "added",
            "identity_provider": "app",
            "identity_identifier": "Bob",
            "access_provider": "app",
            "access_name": "customers:delete",
        }
    ]


def test_effective_access_calculation_handles_large_graph() -> None:
    accesses = [_access(f"A{i}") for i in range(3001)]
    relations = [_relation(f"A{i}", f"A{i + 1}") for i in range(3000)]

    evaluation = calculate_effective_accesses([_assignment("Bob", "A0")], relations, accesses)

    assert len(evaluation.effective_accesses) == 3001
    assert _effective(evaluation, "A3000").access_name == "A3000"
    assert not evaluation.diagnostics


def _effective_names(evaluation) -> list[str]:
    return sorted(item.access_name for item in evaluation.effective_accesses)


def _effective(evaluation, access_name: str):
    matches = [item for item in evaluation.effective_accesses if item.access_name == access_name]
    assert len(matches) == 1
    return matches[0]


def _assignment(identity: str, access_name: str, source: str = "direct") -> AccessAssignment:
    return AccessAssignment(
        "app", access_name, "app", identity, Origin("direct", True, False, source)
    )


def _relation(parent: str, child: str, source: str = "role composition") -> AccessRelation:
    return AccessRelation(
        parent_provider="app",
        parent_access_name=parent,
        child_provider="app",
        child_access_name=child,
        relation_type=AccessRelationType.GRANTS,
        origin=Origin("relation", False, True, source, {"source_kind": source}),
    )


def _access(
    name: str,
    permission: str = "use",
    resource: str | None = None,
    kind: str = "permission",
) -> Access:
    return Access(
        name=name,
        provider="app",
        control_object=ControlObject(kind, resource or name),
        permission=Permission(permission),
        target=Target(resource={"identifier": resource}) if resource else None,
    )


def test_identity_fixture_keeps_domain_types_explicit() -> None:
    identity = Identity("app", "Bob", IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE)
    assert identity.ref().key() == "app:Bob"
