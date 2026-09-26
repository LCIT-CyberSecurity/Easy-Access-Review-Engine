from __future__ import annotations

from hashlib import sha256
from typing import Any

from access_review_engine.domain import (
    Access,
    AccessAssignment,
    AccessRelation,
    AccessRelationType,
    AssignmentType,
    Completeness,
    ControlObject,
    Identity,
    IdentityStatus,
    IdentityType,
    ImportBatch,
    ImportStatus,
    Origin,
    Permission,
    Provider,
    Target,
    now_utc,
    stable_checksum,
)
from access_review_engine.google_artifacts import read_artifact
from access_review_engine.importers.ad import ImportResult

FILES = {
    "users.jsonl",
    "groups.jsonl",
    "memberships.jsonl",
    "admin-roles.jsonl",
    "admin-role-assignments.jsonl",
    "collection-errors.json",
}


def _id(namespace: str, value: str) -> str:
    return sha256(f"{namespace}:{value}".encode()).hexdigest()


def _status(row: dict[str, Any]) -> str:
    if row.get("deleted"):
        return IdentityStatus.DELETED
    if row.get("suspended") or row.get("archived"):
        return IdentityStatus.DISABLED
    return IdentityStatus.ACTIVE


def import_google_workspace_zip(
    path: str, known_identities: list[Identity] | None = None
) -> ImportResult:
    manifest, records = read_artifact(path, "google_workspace", FILES)
    provider_name = str(manifest["provider"])
    provider = Provider(
        provider_name, "google_workspace", manifest.get("display_name") or provider_name
    )
    identities: list[Identity] = []
    by_native: dict[str, Identity] = {}
    by_email: dict[str, Identity] = {}
    for row in records["users.jsonl"]:
        email = str(row.get("primaryEmail") or row.get("email") or "").strip().lower()
        native = str(row.get("id") or row.get("native_id") or "").strip() or None
        if not email:
            raise ValueError("Workspace user is missing primaryEmail")
        identity = Identity(
            provider_name,
            email,
            IdentityType.USER_ACCOUNT,
            _status(row),
            native_id=native,
            display_name=row.get("name") or row.get("displayName"),
            email=email,
            metadata={"aliases": list(row.get("aliases") or [])},
        )
        identities.append(identity)
        if native:
            by_native[native] = identity
        by_email[email] = identity
        for alias in row.get("aliases") or []:
            by_email[str(alias).lower()] = identity
    for row in records["groups.jsonl"]:
        email = str(row.get("email") or row.get("name") or "").strip().lower()
        native = str(row.get("id") or row.get("native_id") or "").strip() or None
        if not email:
            raise ValueError("Workspace group is missing email")
        identity = Identity(
            provider_name,
            email,
            IdentityType.GROUP,
            IdentityStatus.ACTIVE,
            native_id=native,
            display_name=row.get("displayName") or row.get("name"),
            email=email,
            metadata={"aliases": list(row.get("aliases") or [])},
        )
        identities.append(identity)
        if native:
            by_native[native] = identity
        by_email[email] = identity
        for alias in row.get("aliases") or []:
            by_email[str(alias).lower()] = identity

    accesses: list[Access] = []
    assignments: list[AccessAssignment] = []
    relations: list[AccessRelation] = []
    access_by_name: dict[str, Access] = {}
    for group in (identity for identity in identities if identity.type == IdentityType.GROUP):
        for role in ("MEMBER", "MANAGER", "OWNER"):
            name = f"google-group:{group.native_id or group.identifier}:{role}"
            access = Access(
                name=name,
                provider=provider_name,
                control_object=ControlObject(
                    "google_group",
                    group.identifier,
                    group.native_id,
                    group.display_name,
                    {"membership_role": role},
                ),
                permission=Permission(f"google.workspace.group.{role.lower()}", role.title()),
                target=Target(
                    service={"identifier": "Google Workspace"},
                    component={"identifier": "Groups"},
                    resource={"identifier": group.identifier},
                ),
                display_name=f"{group.display_name or group.identifier} — {role.title()}",
                metadata={"membership_role": role, "source_group": group.identifier},
            )
            accesses.append(access)
            access_by_name[name] = access
        for parent_role, child_role in (("OWNER", "MEMBER"), ("MANAGER", "MEMBER")):
            relations.append(
                AccessRelation(
                    provider_name,
                    f"google-group:{group.native_id or group.identifier}:{parent_role}",
                    provider_name,
                    f"google-group:{group.native_id or group.identifier}:{child_role}",
                    AccessRelationType.GRANTS,
                    Origin(
                        AssignmentType.GROUP,
                        False,
                        True,
                        group.identifier,
                        {"semantic": "role_implies_membership"},
                    ),
                    id=_id("workspace-relation", f"{group.identifier}:{parent_role}:{child_role}"),
                )
            )
    for row in records["memberships.jsonl"]:
        group = by_native.get(str(row.get("group_id") or row.get("groupId"))) or by_email.get(
            str(row.get("group_email") or row.get("groupEmail") or "").lower()
        )
        member = by_native.get(str(row.get("member_id") or row.get("memberId"))) or by_email.get(
            str(row.get("member_email") or row.get("email") or "").lower()
        )
        role = str(row.get("role") or "MEMBER").upper()
        if group is None or member is None or role not in {"MEMBER", "MANAGER", "OWNER"}:
            continue
        access_name = f"google-group:{group.native_id or group.identifier}:{role}"
        assignments.append(
            AccessAssignment(
                provider_name,
                access_name,
                member.provider,
                member.identifier,
                Origin(AssignmentType.GROUP, True, False, group.identifier, {"role": role, **row}),
            )
        )
        if member.type == IdentityType.GROUP:
            relations.append(
                AccessRelation(
                    provider_name,
                    f"google-group:{member.native_id or member.identifier}:MEMBER",
                    provider_name,
                    f"google-group:{group.native_id or group.identifier}:MEMBER",
                    AccessRelationType.GRANTS,
                    Origin(
                        AssignmentType.GROUP, False, True, group.identifier, {"nested_group": True}
                    ),
                    id=_id("workspace-nesting", f"{member.identifier}:{access_name}"),
                )
            )
    for row in records["admin-role-assignments.jsonl"]:
        role_id = str(row.get("roleId") or row.get("role_id") or "")
        scope_type = str(row.get("scopeType") or row.get("scope_type") or "CUSTOMER")
        scope_id = str(row.get("orgUnitId") or row.get("org_unit_id") or "")
        if not role_id:
            continue
        semantic = f"{role_id}|{scope_type}|{scope_id}|{row.get('condition') or ''}"
        name = f"google-admin:{_id('workspace-admin', semantic)}"
        if name not in access_by_name:
            access = Access(
                name=name,
                provider=provider_name,
                control_object=ControlObject(
                    "google_workspace_admin_role",
                    role_id,
                    role_id,
                    row.get("roleName") or role_id,
                    {"scope_type": scope_type, "scope_id": scope_id},
                ),
                permission=Permission(role_id, row.get("roleName") or role_id),
                target=Target(
                    service={"identifier": "Google Workspace"},
                    component={"identifier": "Administration"},
                    resource={"identifier": scope_id or scope_type},
                ),
                display_name=row.get("roleName") or role_id,
                metadata={
                    "scope_type": scope_type,
                    "scope_id": scope_id,
                    "condition": row.get("condition"),
                },
            )
            accesses.append(access)
            access_by_name[name] = access
        assignee = by_native.get(
            str(row.get("assignedTo") or row.get("assignee_id"))
        ) or by_email.get(str(row.get("assignedToEmail") or row.get("assignee") or "").lower())
        if assignee:
            assignments.append(
                AccessAssignment(
                    provider_name,
                    name,
                    assignee.provider,
                    assignee.identifier,
                    Origin(
                        AssignmentType.ROLE,
                        True,
                        False,
                        role_id,
                        {"roleAssignmentId": row.get("id"), **row},
                    ),
                )
            )
    errors = records["collection-errors.json"]
    completeness = str(
        manifest.get("completeness") or (Completeness.UNKNOWN if errors else Completeness.FULL)
    )
    if errors and completeness == Completeness.FULL:
        completeness = Completeness.SCOPED
    scope = dict(
        manifest.get("authoritative_scope") or {"type": "providers", "values": [provider_name]}
    )
    scope["completeness"] = completeness
    if errors:
        scope["collection_errors"] = len(errors)
    batch = ImportBatch(
        provider_name,
        "google_workspace_zip",
        ImportStatus.COMPLETED,
        completeness,
        scope,
        stable_checksum({"manifest": manifest, "records": records}),
        completed_at=now_utc(),
    )
    return ImportResult(batch, provider, identities, accesses, assignments, relations)
