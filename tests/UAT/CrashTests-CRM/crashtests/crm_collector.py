from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from access_review_engine.domain import (
    Access,
    AccessAssignment,
    AccessRelation,
    AccessRelationType,
    AuthenticationPosture,
    AuthenticationStatus,
    Completeness,
    ControlObject,
    Identity,
    IdentityStatus,
    IdentityType,
    Origin,
    OwnerRef,
    Permission,
    Provider,
    ProviderType,
    Resource,
    Target,
)

try:
    from .crm_lab import POLICY_DIR, PROVIDER, golden_assignments, role_permissions, users
except ImportError:
    from crm_lab import POLICY_DIR, PROVIDER, golden_assignments, role_permissions, users


@dataclass
class CRMCollection:
    providers: list[Provider]
    identities: list[Identity]
    resources: list[Resource]
    accesses: list[Access]
    assignments: list[AccessAssignment]
    relations: list[AccessRelation]
    completeness: str = Completeness.FULL
    scope: dict[str, object] | None = None
    authentication_posture: AuthenticationPosture | None = None


def collect_crm(
    policy_dir: Path = POLICY_DIR,
    *,
    assignments: list[dict[str, str]] | None = None,
    identities: list[dict[str, str]] | None = None,
    relations: list[AccessRelation] | None = None,
    completeness: str = Completeness.FULL,
    scope: dict[str, object] | None = None,
) -> CRMCollection:
    identity_rows = identities if identities is not None else users(policy_dir)
    assignment_rows = assignments if assignments is not None else golden_assignments(policy_dir)
    accesses = build_accesses(role_permissions(policy_dir))
    reject_access_name_collisions(accesses)
    return CRMCollection(
        providers=[Provider(PROVIDER, ProviderType.GENERIC, "NexaByte IT CRM")],
        identities=[identity_from_row(row) for row in identity_rows],
        resources=build_resources(),
        accesses=accesses,
        assignments=[assignment_from_row(row) for row in assignment_rows],
        relations=relations if relations is not None else build_relations(role_permissions(policy_dir)),
        completeness=completeness,
        scope=scope or {"type": "all", "completeness": str(completeness)},
        authentication_posture=observed_authentication_posture(policy_dir),
    )


def observed_authentication_posture(policy_dir: Path = POLICY_DIR) -> AuthenticationPosture:
    payload = json.loads((policy_dir / "observed-authentication-posture.json").read_text(encoding="utf-8"))
    return AuthenticationPosture(**payload)


def golden_authentication_policy(policy_dir: Path = POLICY_DIR) -> AuthenticationPosture:
    payload = json.loads((policy_dir / "golden-authentication-policy.json").read_text(encoding="utf-8"))
    return AuthenticationPosture(**payload)


def identity_from_row(row: dict[str, str]) -> Identity:
    account_type = row["account_type"]
    identity_type = {
        "human": IdentityType.USER_ACCOUNT,
        "technical": IdentityType.TECHNICAL_ACCOUNT,
        "shared": IdentityType.SHARED_ACCOUNT,
    }[account_type]
    owner = OwnerRef(PROVIDER, row["owner"]) if row.get("owner") else None
    return Identity(
        provider=PROVIDER,
        identifier=row["username"],
        type=identity_type,
        status=IdentityStatus.DISABLED if row["status"] == "disabled" else IdentityStatus.ACTIVE,
        native_id=row["native_id"],
        subject_id=row["native_id"],
        display_name=row["display_name"],
        email=row["email"],
        account_owner=owner,
        metadata={"department": row["department"], "account_type": account_type},
    )


def build_resources() -> list[Resource]:
    return [
        Resource(PROVIDER, "crm_resource", name, native_id=f"CRM-RES-{name}", display_name=name)
        for name in [
            "customer",
            "contacts",
            "prospects",
            "account_owner",
            "contracts",
            "orders",
            "invoices",
            "hardware",
            "serial_numbers",
            "licenses",
            "support",
            "tickets",
            "shipments",
            "replacements",
        ]
    ]


def build_accesses(permission_rows: list[dict[str, str]]) -> list[Access]:
    roles = sorted({row["role"] for row in permission_rows})
    result = [
        Access(
            name=role,
            provider=PROVIDER,
            control_object=ControlObject("role", role, native_id=f"CRM-ROLE-{role}"),
            permission=Permission("member"),
            target=Target(service={"identifier": "nexabyte-crm"}),
            display_name=role,
            access_owner=OwnerRef(PROVIDER, "thierry.admin"),
            metadata={"uat": "CrashTests-CRM", "kind": "role"},
        )
        for role in roles
    ]
    seen_permissions = sorted({(row["resource"], row["permission"]) for row in permission_rows})
    for resource, permission in seen_permissions:
        name = f"{resource}:{permission}"
        result.append(
            Access(
                name=name,
                provider=PROVIDER,
                control_object=ControlObject(
                    "permission",
                    name,
                    native_id=f"CRM-PERM-{resource}-{permission}",
                    metadata={"resource": resource},
                ),
                permission=Permission(permission),
                target=Target(
                    service={"identifier": "nexabyte-crm", "display_name": "NexaByte CRM"},
                    resource={"identifier": resource},
                ),
                display_name=name,
                access_owner=OwnerRef(PROVIDER, "thierry.admin"),
                metadata={"uat": "CrashTests-CRM", "kind": "permission"},
            )
        )
    return result


def build_relations(permission_rows: list[dict[str, str]]) -> list[AccessRelation]:
    return [
        AccessRelation(
            parent_provider=PROVIDER,
            parent_access_name=row["role"],
            child_provider=PROVIDER,
            child_access_name=f"{row['resource']}:{row['permission']}",
            relation_type=AccessRelationType.GRANTS,
            origin=Origin("role", False, True, "CrashTests-CRM role-permissions.csv"),
            metadata={"resource": row["resource"], "permission": row["permission"]},
        )
        for row in permission_rows
    ]


def assignment_from_row(row: dict[str, str]) -> AccessAssignment:
    return AccessAssignment(
        provider=PROVIDER,
        access_name=row["access"],
        identity_provider=PROVIDER,
        identity_identifier=row["identity"],
        origin=Origin(
            "role",
            True,
            False,
            "CrashTests-CRM golden-role-assignments.csv",
            raw={"crm_role": row["access"]},
        ),
    )


def direct_permission_assignment(identity: str, access_name: str) -> AccessAssignment:
    return AccessAssignment(
        provider=PROVIDER,
        access_name=access_name,
        identity_provider=PROVIDER,
        identity_identifier=identity,
        origin=Origin("direct", True, False, "CrashTests-CRM direct ACL", raw={"direct_permission": True}),
    )


def reject_access_name_collisions(accesses: list[Access]) -> None:
    by_key: dict[tuple[str, str], Access] = {}
    for access in accesses:
        key = (access.provider, access.name)
        previous = by_key.get(key)
        if previous is None:
            by_key[key] = access
            continue
        if previous.permission.identifier != access.permission.identifier or previous.target != access.target:
            raise ValueError(
                "Access name collision for provider/name with different permission or target: "
                f"{access.provider}/{access.name}"
            )
