from __future__ import annotations

from access_review_engine.domain import (
    Access,
    AccessAssignment,
    AccessRelation,
    AccessRelationType,
    Campaign,
    ControlObject,
    DecisionValue,
    GoldenSourceAssignment,
    Identity,
    IdentityStatus,
    IdentityType,
    Origin,
    OwnerRef,
    Permission,
    Provider,
    ProviderType,
    Target,
)
from access_review_engine.services import (
    calculate_effective_accesses,
    close_campaign,
    create_decision,
    create_golden_source,
    create_snapshot,
    open_campaign,
    promote_campaign,
    promote_snapshot,
)


def test_access_composition_does_not_regress_direct_golden_lifecycle() -> None:
    manager = Identity("crm", "manager", IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE)
    bob = Identity("crm", "Bob", IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE)
    sales_manager = _access("Sales-Manager", kind="role", owner=OwnerRef("crm", "manager"))
    customer_read = _access("customers:read", permission="read", resource="customers")
    customer_write = _access("customers:write", permission="write", resource="customers")
    assignment = AccessAssignment(
        "crm", "Sales-Manager", "crm", "Bob", Origin("role", True, False, "HR role feed")
    )
    relations = [
        _relation("Sales-Manager", "customers:read"),
        _relation("Sales-Manager", "customers:write"),
    ]

    snapshot = create_snapshot(
        [Provider("crm", ProviderType.GENERIC)],
        [manager, bob],
        [],
        [sales_manager, customer_read, customer_write],
        [assignment],
        ["import-1"],
        access_relations=relations,
    )
    effective = calculate_effective_accesses(
        snapshot.access_assignments, snapshot.access_relations, snapshot.accesses
    )
    assert sorted(item.access_name for item in effective.effective_accesses) == [
        "Sales-Manager",
        "customers:read",
        "customers:write",
    ]
    assert len(snapshot.access_assignments) == 1

    golden_source = create_golden_source("crm-baseline")
    golden_v1 = promote_snapshot(golden_source, snapshot)
    assert len(golden_v1.assignments) == 1
    assert golden_v1.assignments[0].key() == GoldenSourceAssignment(
        "crm", "Sales-Manager", "crm", "Bob"
    ).key()

    reviewed_snapshot = create_snapshot(
        [Provider("crm", ProviderType.GENERIC)],
        [manager, bob],
        [],
        [sales_manager, customer_read, customer_write],
        [assignment],
        ["import-2"],
        golden_v1,
        access_relations=relations,
    )
    campaign, items = open_campaign(
        Campaign(
            "crm-q1",
            reviewed_snapshot.id,
            golden_source_version_id=golden_v1.id,
            manager=OwnerRef("crm", "manager"),
        ),
        reviewed_snapshot,
    )
    assert len(items) == 1
    assert items[0].access_name == "Sales-Manager"
    decision = create_decision(items[0], DecisionValue.APPROVE, None, "manager")
    close_campaign(campaign, items, [decision])
    golden_v2 = promote_campaign(golden_source, campaign, items, [decision], golden_v1)
    assert len(golden_v2.assignments) == 1
    assert golden_v2.assignments[0].key() == golden_v1.assignments[0].key()


def _relation(parent: str, child: str) -> AccessRelation:
    return AccessRelation(
        parent_provider="crm",
        parent_access_name=parent,
        child_provider="crm",
        child_access_name=child,
        relation_type=AccessRelationType.GRANTS,
        origin=Origin("relation", False, True, "CRM role definition"),
    )


def _access(
    name: str,
    permission: str = "use",
    resource: str | None = None,
    kind: str = "permission",
    owner: OwnerRef | None = None,
) -> Access:
    return Access(
        name=name,
        provider="crm",
        control_object=ControlObject(kind, resource or name),
        permission=Permission(permission),
        target=Target(resource={"identifier": resource}) if resource else None,
        access_owner=owner,
    )
