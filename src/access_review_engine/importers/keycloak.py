"""Normalize a versioned, read-only Keycloak artifact into the EARE model.

The artifact deliberately keeps Keycloak's objects and mappings separate.  This
module is the only place where those objects acquire EARE access names; direct
assignments remain observations and inheritance is represented by relations.
"""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Any
from zipfile import BadZipFile, ZipFile

import yaml

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
from access_review_engine.importers.ad import ImportResult

FILES = {
    "users.jsonl",
    "groups.jsonl",
    "group-memberships.jsonl",
    "clients.jsonl",
    "realm-roles.jsonl",
    "client-roles.jsonl",
    "user-role-mappings.jsonl",
    "group-role-mappings.jsonl",
    "composite-role-relations.jsonl",
    "service-accounts.jsonl",
    "collection-errors.json",
}

_SURFACE_FILES = {
    "users": "users.jsonl",
    "groups": "groups.jsonl",
    "memberships": "group-memberships.jsonl",
    "clients": "clients.jsonl",
    "realm_roles": "realm-roles.jsonl",
    "client_roles": "client-roles.jsonl",
    "user_role_mappings": "user-role-mappings.jsonl",
    "group_role_mappings": "group-role-mappings.jsonl",
    "composite_roles": "composite-role-relations.jsonl",
    "service_accounts": "service-accounts.jsonl",
}


def _stable_id(namespace: str, value: str) -> str:
    return sha256(f"keycloak:{namespace}:{value}".encode()).hexdigest()


def _text(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _status(row: dict[str, Any]) -> str:
    if row.get("deleted"):
        return IdentityStatus.DELETED
    if row.get("enabled") is False or row.get("disabled") is True:
        return IdentityStatus.DISABLED
    return IdentityStatus.ACTIVE


def _role_key(row: dict[str, Any]) -> tuple[str, str, str]:
    kind = _text(row, "role_kind", "kind", "type").lower() or "realm"
    role_id = _text(row, "role_id", "id")
    client_id = _text(row, "client_id", "clientId") if kind == "client" else ""
    return kind, role_id, client_id


def _read_artifact(path: str | Path) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]]]:
    try:
        with ZipFile(path) as archive:
            names = [item.filename for item in archive.infolist()]
            if len(names) != len(set(names)):
                raise ValueError("Artifact contains duplicate filenames")
            if any(name.startswith("/") or ".." in Path(name).parts for name in names):
                raise ValueError("Unsafe ZIP path detected")
            if set(names) - FILES - {"manifest.yaml"}:
                raise ValueError("Artifact contains unexpected files")
            if "manifest.yaml" not in names:
                raise ValueError("Artifact is missing manifest.yaml")
            manifest = yaml.safe_load(archive.read("manifest.yaml").decode("utf-8-sig"))
            if not isinstance(manifest, dict) or manifest.get("source_type") != "keycloak":
                raise ValueError("Artifact manifest has an invalid source_type")
            if manifest.get("schema_version") != 1:
                raise ValueError("Unsupported Keycloak artifact schema_version")
            provider = manifest.get("provider")
            realm = manifest.get("realm")
            if (
                not isinstance(provider, str)
                or not provider.strip()
                or not isinstance(realm, str)
                or not realm.strip()
            ):
                raise ValueError("Artifact manifest must define provider and realm")
            requested = manifest.get("requested_surfaces", [])
            completed = manifest.get("completed_surfaces", [])
            if (
                not isinstance(requested, list)
                or not isinstance(completed, list)
                or not set(completed).issubset(set(requested))
            ):
                raise ValueError("Artifact manifest has invalid surface completion data")
            if manifest.get("completeness") == "full" and set(completed) != set(requested):
                raise ValueError("FULL Keycloak artifact does not complete every requested surface")
            records: dict[str, list[dict[str, Any]]] = {}
            for filename in FILES:
                if filename not in names:
                    records[filename] = []
                    continue
                if filename == "collection-errors.json":
                    value = json.loads(archive.read(filename).decode("utf-8"))
                    if not isinstance(value, list) or not all(
                        isinstance(item, dict) for item in value
                    ):
                        raise ValueError("collection-errors.json must contain an array of objects")
                    records[filename] = value
                    continue
                rows: list[dict[str, Any]] = []
                for line in archive.read(filename).splitlines():
                    if not line.strip():
                        continue
                    value = json.loads(line.decode("utf-8"))
                    if not isinstance(value, dict):
                        raise ValueError(f"Artifact record in {filename} must be an object")
                    rows.append(value)
                records[filename] = rows
            counts = manifest.get("counts")
            if isinstance(counts, dict):
                for surface, filename in _SURFACE_FILES.items():
                    if surface in counts and int(counts[surface]) != len(records[filename]):
                        raise ValueError(f"Artifact count mismatch for {surface}")
            return manifest, records
    except BadZipFile as exc:
        raise ValueError("Invalid Keycloak artifact ZIP") from exc


def _unique_rows(rows: list[dict[str, Any]], filename: str) -> list[dict[str, Any]]:
    """Deduplicate identical API retries but reject conflicting duplicate IDs."""
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        identifier = _text(row, "id", "role_id", "user_id", "group_id")
        if not identifier:
            raise ValueError(f"{filename} contains a record without a stable id")
        previous = result.get(identifier)
        if previous is not None and previous != row:
            raise ValueError(f"{filename} contains conflicting duplicate id {identifier}")
        result[identifier] = row
    return list(result.values())


def import_keycloak_zip(path: str | Path) -> ImportResult:
    manifest, records = _read_artifact(path)
    provider_name = str(manifest["provider"])
    realm = str(manifest["realm"])
    errors = records["collection-errors.json"]
    provider = Provider(provider_name, "keycloak", provider_name)

    users = _unique_rows(records["users.jsonl"], "users.jsonl")
    groups = _unique_rows(records["groups.jsonl"], "groups.jsonl")
    _unique_rows(records["clients.jsonl"], "clients.jsonl")
    realm_roles = _unique_rows(records["realm-roles.jsonl"], "realm-roles.jsonl")
    client_roles = _unique_rows(records["client-roles.jsonl"], "client-roles.jsonl")
    service_rows = _unique_rows(records["service-accounts.jsonl"], "service-accounts.jsonl")
    service_ids = {_text(row, "user_id", "id") for row in service_rows}

    identities: list[Identity] = []
    by_id: dict[str, Identity] = {}
    for row in users:
        native_id = _text(row, "id")
        if not native_id:
            raise ValueError("Keycloak user is missing id")
        technical = bool(row.get("service_account")) or native_id in service_ids
        identifier = _text(row, "username") or native_id
        identity = Identity(
            provider_name,
            identifier,
            IdentityType.TECHNICAL_ACCOUNT if technical else IdentityType.USER_ACCOUNT,
            _status(row),
            native_id=native_id,
            display_name=_text(row, "display_name", "displayName", "username") or native_id,
            email=_text(row, "email") or None,
            metadata={
                "keycloak_realm": realm,
                "first_name": row.get("first_name", row.get("firstName")),
                "last_name": row.get("last_name", row.get("lastName")),
                "federation_link": row.get("federation_link", row.get("federationLink")),
                "service_account": technical,
            },
        )
        identities.append(identity)
        by_id[native_id] = identity
    for row in groups:
        native_id = _text(row, "id")
        if not native_id:
            raise ValueError("Keycloak group is missing id")
        identity = Identity(
            provider_name,
            f"group:{native_id}",
            IdentityType.GROUP,
            _status(row),
            native_id=native_id,
            display_name=_text(row, "name") or native_id,
            metadata={"keycloak_realm": realm, "path": row.get("path")},
        )
        identities.append(identity)
        by_id[native_id] = identity

    accesses: list[Access] = []
    assignments: list[AccessAssignment] = []
    relations: list[AccessRelation] = []
    access_by_key: dict[str, Access] = {}

    def add_access(
        name: str,
        native_id: str,
        kind: str,
        display_name: str,
        client_id: str | None = None,
    ) -> None:
        if name in access_by_key:
            return
        access_by_key[name] = Access(
            name=name,
            provider=provider_name,
            control_object=ControlObject(
                type=kind,
                identifier=name,
                native_id=native_id,
                display_name=display_name,
                metadata=(
                    {"realm": realm, "client_id": client_id}
                    if client_id
                    else {"realm": realm}
                ),
            ),
            permission=Permission("member" if kind == "keycloak_group" else "role", display_name),
            target=Target(
                service={"identifier": "Keycloak", "realm": realm},
                component={"identifier": client_id or "realm"},
                resource={"identifier": display_name},
            ),
            display_name=display_name,
        )
        accesses.append(access_by_key[name])

    for row in groups:
        group_id = _text(row, "id")
        add_access(
            f"group:{group_id}:member",
            group_id,
            "keycloak_group",
            _text(row, "name") or group_id,
        )
    role_access: dict[tuple[str, str, str], str] = {}
    for row in realm_roles + client_roles:
        kind, role_id, client_id = _role_key(row)
        if not role_id:
            continue
        if kind not in {"realm", "client"}:
            raise ValueError(f"Unsupported Keycloak role kind: {kind}")
        name = (
            f"realm:{realm}:role:{role_id}"
            if kind == "realm"
            else f"client:{client_id}:role:{role_id}"
        )
        label = _text(row, "name") or role_id
        add_access(
            name,
            role_id,
            "keycloak_realm_role" if kind == "realm" else "keycloak_client_role",
            label,
            client_id or None,
        )
        role_access[(kind, role_id, client_id)] = name

    def role_access_for(row: dict[str, Any]) -> str | None:
        return role_access.get(_role_key(row))

    for row in _unique_rows(records["group-memberships.jsonl"], "group-memberships.jsonl"):
        member = by_id.get(_text(row, "member_id", "user_id"))
        group_id = _text(row, "group_id")
        group = by_id.get(group_id)
        if member is None or group is None or group.type != IdentityType.GROUP:
            continue
        access_name = f"group:{group_id}:member"
        assignments.append(AccessAssignment(
            provider_name, access_name, member.provider, member.identifier,
            Origin(AssignmentType.GROUP, True, False, group.identifier, dict(row)),
            id=_stable_id("membership", stable_checksum(row)),
        ))
        if member.type == IdentityType.GROUP:
            relations.append(AccessRelation(
                provider_name, f"group:{member.native_id}:member", provider_name, access_name,
                AccessRelationType.GRANTS,
                Origin(
                    AssignmentType.GROUP,
                    False,
                    True,
                    member.identifier,
                    {"nested_group": True, **row},
                ),
                id=_stable_id("nested-group", stable_checksum(row)),
            ))

    for filename, identity_key in (
        ("user-role-mappings.jsonl", "user_id"),
        ("group-role-mappings.jsonl", "group_id"),
    ):
        for row in _unique_rows(records[filename], filename):
            role_name = role_access_for(row)
            subject = by_id.get(_text(row, identity_key))
            if role_name is None or subject is None:
                continue
            assignments.append(AccessAssignment(
                provider_name, role_name, subject.provider, subject.identifier,
                Origin(AssignmentType.ROLE, True, False, subject.identifier, dict(row)),
                id=_stable_id("role-mapping", f"{filename}:{stable_checksum(row)}"),
            ))
            if filename == "group-role-mappings.jsonl":
                relations.append(AccessRelation(
                    provider_name, f"group:{subject.native_id}:member", provider_name, role_name,
                    AccessRelationType.GRANTS,
                    Origin(
                        AssignmentType.GROUP,
                        False,
                        True,
                        subject.identifier,
                        {"group_role_mapping": True, **row},
                    ),
                    id=_stable_id("group-role", stable_checksum(row)),
                ))

    for row in _unique_rows(
        records["composite-role-relations.jsonl"], "composite-role-relations.jsonl"
    ):
        parent = role_access_for(
            {
                "role_kind": row.get("parent_kind"),
                "role_id": row.get("parent_role_id"),
                "client_id": row.get("parent_client_id"),
            }
        )
        child = role_access_for(
            {
                "role_kind": row.get("child_kind"),
                "role_id": row.get("child_role_id"),
                "client_id": row.get("child_client_id"),
            }
        )
        if parent is None or child is None:
            continue
        relations.append(AccessRelation(
            provider_name, parent, provider_name, child, AccessRelationType.GRANTS,
            Origin(AssignmentType.ROLE, False, True, parent, {"composite": True, **row}),
            id=_stable_id("composite", stable_checksum(row)),
        ))

    completeness = str(
        manifest.get("completeness") or (Completeness.UNKNOWN if errors else Completeness.FULL)
    )
    if errors and completeness == str(Completeness.FULL):
        completeness = str(Completeness.SCOPED)
    scope = dict(
        manifest.get("authoritative_scope")
        or {
            "connector_type": "keycloak",
            "realm": realm,
            "surfaces": manifest.get("requested_surfaces", []),
        }
    )
    scope["completeness"] = completeness
    checksum_manifest = json.loads(json.dumps(manifest, default=str))
    batch = ImportBatch(
        provider_name, "keycloak_zip", ImportStatus.COMPLETED, completeness, scope,
        stable_checksum({"manifest": checksum_manifest, "records": records}),
        completed_at=now_utc(),
    )
    return ImportResult(batch, provider, identities, accesses, assignments, relations)
