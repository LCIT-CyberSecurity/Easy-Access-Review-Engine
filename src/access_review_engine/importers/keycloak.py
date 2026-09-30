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
    SYSTEM_CAPABILITIES,
    Access,
    AccessAssignment,
    AccessRelation,
    AccessRelationType,
    AssignmentType,
    Capability,
    Completeness,
    ControlObject,
    ExpectedAccessModel,
    FunctionalModelCompleteness,
    FunctionalRight,
    Identity,
    IdentityStatus,
    IdentityType,
    ImportBatch,
    ImportStatus,
    Origin,
    Permission,
    PermissionCapabilityMapping,
    Provenance,
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
    "authorization-resource-servers.jsonl",
    "authorization-resources.jsonl",
    "authorization-scopes.jsonl",
    "authorization-policies.jsonl",
    "authorization-permissions.jsonl",
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

KEYCLOAK_V1_REQUIRED_SURFACES = frozenset(_SURFACE_FILES)
KEYCLOAK_AUTHZ_FILES = {
    "authorization-resource-servers.jsonl": "authorization_resource_servers",
    "authorization-resources.jsonl": "authorization_resources",
    "authorization-scopes.jsonl": "authorization_scopes",
    "authorization-policies.jsonl": "authorization_policies",
    "authorization-permissions.jsonl": "authorization_permissions",
}
SUPPORTED_COMPLETENESS = frozenset({"full", "scoped", "unknown"})
MAX_ARCHIVE_BYTES = 500_000_000
MAX_ARCHIVE_FILES = 32
MAX_ENTRY_BYTES = 250_000_000
MAX_MANIFEST_BYTES = 1_000_000
MAX_UNCOMPRESSED_BYTES = 1_500_000_000
MAX_RECORD_BYTES = 2_000_000


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


def _row_identifier(filename: str, row: dict[str, Any]) -> str:
    identifier = _text(row, "id")
    if identifier:
        return identifier
    if filename == "group-memberships.jsonl":
        return f"membership:{_text(row, 'member_id', 'user_id')}:{_text(row, 'group_id')}"
    if filename in {"user-role-mappings.jsonl", "group-role-mappings.jsonl"}:
        kind, role_id, client_id = _role_key(row)
        subject = _text(row, "user_id", "group_id")
        return f"mapping:{subject}:{kind}:{role_id}:{client_id}"
    if filename == "composite-role-relations.jsonl":
        return (
            f"composite:{_text(row, 'parent_kind')}:{_text(row, 'parent_role_id')}"
            f":{_text(row, 'parent_client_id')}:{_text(row, 'child_kind')}"
            f":{_text(row, 'child_role_id')}:{_text(row, 'child_client_id')}"
        )
    if filename == "service-accounts.jsonl":
        return f"service:{_text(row, 'user_id', 'id')}:{_text(row, 'client_id', 'clientId')}"
    return _text(row, "role_id", "user_id", "group_id")


def _read_artifact(path: str | Path) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]]]:
    if Path(path).stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("Keycloak artifact exceeds configured maximum size")
    try:
        with ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ARCHIVE_FILES:
                raise ValueError("Keycloak artifact contains too many files")
            names = [item.filename for item in infos]
            if len(names) != len(set(names)):
                raise ValueError("Artifact contains duplicate filenames")
            if any(name.startswith("/") or ".." in Path(name).parts for name in names):
                raise ValueError("Unsafe ZIP path detected")
            if set(names) - FILES - {"manifest.yaml"}:
                raise ValueError("Artifact contains unexpected files")
            if "manifest.yaml" not in names:
                raise ValueError("Artifact is missing manifest.yaml")
            total_uncompressed = 0
            info_by_name = {info.filename: info for info in infos}
            for info in infos:
                if info.file_size > MAX_ENTRY_BYTES:
                    raise ValueError("Artifact member exceeds configured maximum size")
                total_uncompressed += info.file_size
            if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
                raise ValueError("Artifact uncompressed size exceeds configured maximum size")
            manifest_info = info_by_name["manifest.yaml"]
            if manifest_info.file_size > MAX_MANIFEST_BYTES:
                raise ValueError("Keycloak manifest exceeds configured maximum size")
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
                or any(not isinstance(item, str) for item in (*requested, *completed))
                or len(requested) != len(set(requested))
                or len(completed) != len(set(completed))
                or set(requested) - KEYCLOAK_V1_REQUIRED_SURFACES
                or set(completed) - KEYCLOAK_V1_REQUIRED_SURFACES
                or not set(completed).issubset(set(requested))
            ):
                raise ValueError("Artifact manifest has invalid surface completion data")
            completeness = manifest.get("completeness")
            if completeness not in SUPPORTED_COMPLETENESS:
                raise ValueError("Artifact manifest has invalid completeness")
            if completeness == "full" and (
                set(requested) != KEYCLOAK_V1_REQUIRED_SURFACES
                or set(completed) != KEYCLOAK_V1_REQUIRED_SURFACES
            ):
                raise ValueError("FULL Keycloak artifact must complete every V1 surface")
            for surface in completed:
                filename = _SURFACE_FILES[surface]
                if filename not in names:
                    raise ValueError(f"Completed Keycloak surface {surface} is missing {filename}")
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
                    if len(line) > MAX_RECORD_BYTES:
                        raise ValueError("Keycloak JSONL record exceeds configured maximum size")
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
            elif completeness == "full":
                raise ValueError("FULL Keycloak artifact must define counts for every surface")
            if completeness == "full" and set(counts) != KEYCLOAK_V1_REQUIRED_SURFACES:
                raise ValueError("FULL Keycloak artifact has incomplete counts")
            authz_counts = manifest.get("authorization_counts", {})
            if authz_counts is not None and not isinstance(authz_counts, dict):
                raise ValueError("Manifest authorization_counts must be an object")
            if isinstance(authz_counts, dict):
                for filename, surface in KEYCLOAK_AUTHZ_FILES.items():
                    if surface in authz_counts and int(authz_counts[surface]) != len(
                        records[filename]
                    ):
                        raise ValueError(f"Authorization count mismatch for {surface}")
            authz_status = manifest.get("authorization_services", {})
            if authz_status is not None:
                if not isinstance(authz_status, dict) or any(
                    not isinstance(value, dict)
                    or value.get("status") not in {"not_enabled", "collected", "error"}
                    for value in authz_status.values()
                ):
                    raise ValueError("Manifest authorization_services has invalid status data")
            declared_errors = manifest.get("collection_errors")
            errors = records["collection-errors.json"]
            if errors and declared_errors is None:
                raise ValueError("Manifest must declare collection_errors when errors are present")
            if declared_errors is not None and (
                isinstance(declared_errors, int)
                and declared_errors != len(errors)
                or isinstance(declared_errors, list)
                and declared_errors != errors
                or not isinstance(declared_errors, (int, list))
            ):
                raise ValueError("Manifest collection_errors does not match collection-errors.json")
            if errors and completeness == "full":
                raise ValueError("Keycloak artifact with collection errors cannot be FULL")
            return manifest, records
    except BadZipFile as exc:
        raise ValueError("Invalid Keycloak artifact ZIP") from exc


def _unique_rows(rows: list[dict[str, Any]], filename: str) -> list[dict[str, Any]]:
    """Deduplicate identical API retries but reject conflicting duplicate IDs."""
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        identifier = _row_identifier(filename, row)
        if not identifier:
            raise ValueError(f"{filename} contains a record without a stable id")
        previous = result.get(identifier)
        if previous is not None and previous != row:
            raise ValueError(f"{filename} contains conflicting duplicate id {identifier}")
        result[identifier] = row
    return list(result.values())


def _authorization_refs(value: Any) -> list[str]:
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    if isinstance(value, dict):
        reference = _text(value, "id", "name")
        return [reference] if reference else []
    if not isinstance(value, list):
        return []
    refs: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            refs.append(item.strip())
        elif isinstance(item, dict):
            reference = _text(item, "id", "name")
            if reference:
                refs.append(reference)
    return refs


def _role_policy_role(policy: dict[str, Any]) -> str | None:
    if _text(policy, "type", "policyType").casefold() != "role":
        return None
    if _text(policy, "logic").casefold() not in {"", "positive"}:
        return None
    config = policy.get("config")
    if isinstance(config, str):
        try:
            config = json.loads(config)
        except json.JSONDecodeError:
            return None
    if not isinstance(config, dict):
        return None
    roles = config.get("roles")
    if isinstance(roles, str):
        try:
            roles = json.loads(roles)
        except json.JSONDecodeError:
            return None
    if not isinstance(roles, list) or len(roles) != 1:
        return None
    role = roles[0]
    if isinstance(role, dict):
        # Keycloak role policies expose the native role UUID.  A display name
        # is not a safe fallback: the same role name may exist in multiple
        # clients, and a name-only match could grant a right to the wrong
        # Access.  Plain strings are retained because some Keycloak versions
        # return the native reference directly as a string.
        return _text(role, "id", "roleId") or None
    return str(role).strip() or None


def _authorization_models(
    records: dict[str, list[dict[str, Any]]],
    clients_by_id: dict[str, dict[str, Any]],
    role_access: dict[tuple[str, str, str], str],
    provider_name: str,
    realm: str,
) -> tuple[
    list[ExpectedAccessModel],
    list[Capability],
    list[PermissionCapabilityMapping],
]:
    resources = {
        (_text(row, "client_uuid", "clientId"), _text(row, "id", "_id")): row
        for row in records["authorization-resources.jsonl"]
        if _text(row, "id", "_id")
    }
    scopes = {
        (_text(row, "client_uuid", "clientId"), _text(row, "id")): row
        for row in records["authorization-scopes.jsonl"]
        if _text(row, "id")
    }
    policies = {
        (_text(row, "client_uuid", "clientId"), _text(row, "id")): row
        for row in records["authorization-policies.jsonl"]
        if _text(row, "id")
    }
    resource_servers = {
        _text(row, "client_uuid", "clientId"): row
        for row in records.get("authorization-resource-servers.jsonl", [])
        if _text(row, "client_uuid", "clientId")
    }
    system_capabilities = {item.id: item for item in SYSTEM_CAPABILITIES}
    capabilities: dict[str, Capability] = {}
    mappings: dict[tuple[str, str], PermissionCapabilityMapping] = {}
    scope_capabilities: dict[tuple[str, str], tuple[str, str]] = {}
    for (client_uuid, scope_id), scope in scopes.items():
        scope_name = _text(scope, "name") or scope_id
        native_permission = f"keycloak:{realm}:{client_uuid}:scope:{scope_id}"
        if scope_name in system_capabilities:
            capability_id = scope_name
        else:
            digest = sha256(f"{realm}:{client_uuid}:{scope_id}".encode()).hexdigest()[:20]
            capability_id = f"keycloak_scope_{digest}"
            capabilities[capability_id] = Capability(
                capability_id,
                scope_name,
                f"Native Keycloak Authorization Scope {scope_name!r}.",
            )
        scope_capabilities[(client_uuid, scope_id)] = (capability_id, native_permission)
        mappings[(provider_name, native_permission)] = PermissionCapabilityMapping(
            provider_name,
            native_permission,
            (capability_id,),
            Provenance.MAPPED,
        )
    rights_by_access: dict[str, list[FunctionalRight]] = {}
    state_by_access: dict[str, dict[str, bool]] = {}

    def related_roles(
        client_uuid: str,
        policy_id: str,
        visited: set[str] | None = None,
    ) -> set[str]:
        """Find role dependencies for completeness only; complex policies never grant rights."""
        seen = visited or set()
        if policy_id in seen or len(seen) >= 8:
            return set()
        seen = seen | {policy_id}
        policy = policies.get((client_uuid, policy_id), {})
        direct = _role_policy_role(policy)
        if direct:
            return {direct}
        config = policy.get("config", {})
        if isinstance(config, str):
            try:
                config = json.loads(config)
            except json.JSONDecodeError:
                return set()
        if not isinstance(config, dict):
            return set()
        references = _authorization_refs(policy.get("policies")) or _authorization_refs(
            config.get("policies")
        )
        return set().union(*(related_roles(client_uuid, ref, seen) for ref in references))

    def referenced_roles(
        client_uuid: str,
        policy_id: str,
        visited: set[str] | None = None,
    ) -> set[str]:
        """Return all native role references without claiming a grant is resolved."""
        seen = visited or set()
        if policy_id in seen or len(seen) >= 8:
            return set()
        seen = seen | {policy_id}
        policy = policies.get((client_uuid, policy_id), {})
        config = policy.get("config", {})
        if isinstance(config, str):
            try:
                config = json.loads(config)
            except json.JSONDecodeError:
                config = {}
        roles = config.get("roles", []) if isinstance(config, dict) else []
        if isinstance(roles, str):
            try:
                roles = json.loads(roles)
            except json.JSONDecodeError:
                roles = []
        result = {
            (_text(role, "id", "roleId") if isinstance(role, dict) else str(role).strip())
            for role in (roles if isinstance(roles, list) else [])
            if (_text(role, "id", "roleId") if isinstance(role, dict) else str(role).strip())
        }
        references = _authorization_refs(policy.get("policies")) or _authorization_refs(
            config.get("policies") if isinstance(config, dict) else None
        )
        for reference in references:
            result.update(referenced_roles(client_uuid, reference, seen))
        return result

    permission_entries: list[tuple[dict[str, Any], str, list[str], list[str], list[str]]] = []
    overlapping_complex: set[tuple[str, str]] = set()
    for permission in records["authorization-permissions.jsonl"]:
        client_uuid = _text(permission, "client_uuid", "clientId")
        policy_refs = _authorization_refs(permission.get("policies", permission.get("policyIds")))
        resource_refs = _authorization_refs(
            permission.get("resources", permission.get("resourceIds"))
        )
        scope_refs = _authorization_refs(permission.get("scopes", permission.get("scopeIds")))
        strict_policy = (
            policies.get((client_uuid, policy_refs[0])) if len(policy_refs) == 1 else None
        )
        strict_role = _role_policy_role(strict_policy or {}) if strict_policy else None
        complex_permission = (
            strict_role is None
            or not resource_refs
            or not scope_refs
            or _text(resource_servers.get(client_uuid, {}), "policyEnforcementMode").upper()
            not in {"", "ENFORCING"}
        )
        if complex_permission:
            for resource_ref in resource_refs:
                for scope_ref in scope_refs:
                    overlapping_complex.add((client_uuid, resource_ref + "\0" + scope_ref))
        permission_entries.append((permission, client_uuid, policy_refs, resource_refs, scope_refs))

    for (
        permission,
        client_uuid,
        policies_for_permission,
        resource_refs,
        scope_refs,
    ) in permission_entries:
        client = clients_by_id.get(client_uuid, {})
        policy = (
            policies.get((client_uuid, policies_for_permission[0]))
            if len(policies_for_permission) == 1
            else None
        )
        role_ref = _role_policy_role(policy or {}) if policy else None
        if role_ref is None:
            referenced = set().union(
                *(referenced_roles(client_uuid, policy_id) for policy_id in policies_for_permission)
            )
            referenced.update(
                related
                for policy_id in policies_for_permission
                for related in related_roles(client_uuid, policy_id)
            )
            for related_role in referenced:
                for key, name in role_access.items():
                    if key[1] == related_role and key[2] in {"", client_uuid}:
                        state = state_by_access.setdefault(name, {"complex": False, "seen": False})
                        state["complex"] = True
                        state["seen"] = True
            continue
        role_key = next(
            (key for key in role_access if key[1] == role_ref and key[2] in {"", client_uuid}),
            None,
        )
        if role_key is None and role_ref:
            role_key = next(
                (key for key in role_access if key[2] == client_uuid and key[1] == role_ref),
                None,
            )
        if role_key is None:
            continue
        access_name = role_access[role_key]
        state = state_by_access.setdefault(access_name, {"complex": False, "seen": False})
        state["seen"] = True
        if not resource_refs or not scope_refs:
            state["complex"] = True
            continue
        if _text(resource_servers.get(client_uuid, {}), "policyEnforcementMode").upper() not in {
            "",
            "ENFORCING",
        }:
            state["complex"] = True
        for resource_ref in resource_refs:
            resource = resources.get((client_uuid, resource_ref))
            if resource is None:
                state["complex"] = True
                continue
            for scope_ref in scope_refs:
                scope = scopes.get((client_uuid, scope_ref))
                capability_mapping = scope_capabilities.get((client_uuid, scope_ref))
                if (
                    scope is None
                    or capability_mapping is None
                    or (client_uuid, resource_ref + "\0" + scope_ref) in overlapping_complex
                ):
                    state["complex"] = True
                    if scope is None or capability_mapping is None:
                        continue
                capability_id, native_permission = capability_mapping
                policy_id = policies_for_permission[0]
                authorization_metadata = {
                    "realm": realm,
                    "client_uuid": client_uuid,
                    "client_id": _text(permission, "clientId") or _text(client, "clientId"),
                    "resource_id": resource_ref,
                    "resource_name": _text(resource, "name", "displayName") or resource_ref,
                    "scope_id": scope_ref,
                    "scope_name": _text(scope, "name") or scope_ref,
                    "permission_id": _text(permission, "id"),
                    "permission_name": _text(permission, "name"),
                    "permission_type": _text(permission, "type"),
                    "permission_decision_strategy": _text(
                        permission, "decisionStrategy", "decision_strategy"
                    ),
                    "policy_id": policy_id,
                    "policy_name": _text(policy or {}, "name"),
                    "policy_type": _text(policy or {}, "type", "policyType"),
                    "policy_logic": _text(policy or {}, "logic"),
                    "policy_decision_strategy": _text(
                        policy or {}, "decisionStrategy", "decision_strategy"
                    ),
                }
                target = Target(
                    service={
                        "identifier": "Keycloak",
                        "realm": realm,
                        "metadata": {"source": "keycloak_authorization_services"},
                    },
                    component={
                        "identifier": client_uuid,
                        "display_name": _text(client, "name", "clientId") or client_uuid,
                        "metadata": {
                            "realm": realm,
                            "client_uuid": client_uuid,
                            "client_id": _text(permission, "clientId") or _text(client, "clientId"),
                        },
                    },
                    resource={
                        "identifier": resource_ref,
                        "display_name": _text(resource, "name", "displayName") or resource_ref,
                        "metadata": {"keycloak_authorization": authorization_metadata},
                    },
                )
                rights_by_access.setdefault(access_name, []).append(
                    FunctionalRight(
                        target=target,
                        capability_id=capability_id,
                        provenance=Provenance.MAPPED,
                        native_permission=native_permission,
                    )
                )
    models: list[ExpectedAccessModel] = []
    for access_name, state in state_by_access.items():
        rights = tuple(rights_by_access.get(access_name, ()))
        if not rights:
            completeness = FunctionalModelCompleteness.NOT_DEFINED
        elif state["complex"]:
            completeness = FunctionalModelCompleteness.PARTIAL
        else:
            completeness = FunctionalModelCompleteness.COMPLETE
        models.append(ExpectedAccessModel(provider_name, access_name, completeness, rights))
    return models, list(capabilities.values()), list(mappings.values())


def _complex_authorization_permissions(
    records: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    policies = {
        (_text(row, "client_uuid", "clientId"), _text(row, "id")): row
        for row in records["authorization-policies.jsonl"]
        if _text(row, "id")
    }
    result = []
    for permission in records["authorization-permissions.jsonl"]:
        client_uuid = _text(permission, "client_uuid", "clientId")
        policy_refs = _authorization_refs(permission.get("policies", permission.get("policyIds")))
        policy = policies.get((client_uuid, policy_refs[0])) if len(policy_refs) == 1 else None
        resource_ids = _authorization_refs(
            permission.get("resources", permission.get("resourceIds"))
        )
        scope_ids = _authorization_refs(permission.get("scopes", permission.get("scopeIds")))
        if (
            policy is not None
            and _role_policy_role(policy) is not None
            and resource_ids
            and scope_ids
        ):
            continue
        result.append(
            {
                "client_uuid": client_uuid,
                "client_id": _text(permission, "clientId"),
                "permission_id": _text(permission, "id"),
                "name": _text(permission, "name"),
                "type": _text(permission, "type"),
                "resource_ids": resource_ids,
                "scope_ids": scope_ids,
                "policy_ids": policy_refs,
                "decision_strategy": _text(
                    permission, "decisionStrategy", "decision_strategy"
                ),
                "policy_types": [
                    _text(policies.get((client_uuid, policy_id), {}), "type", "policyType")
                    for policy_id in policy_refs
                ],
            }
        )
    return result


def import_keycloak_zip(path: str | Path) -> ImportResult:
    manifest, records = _read_artifact(path)
    provider_name = str(manifest["provider"])
    realm = str(manifest["realm"])
    errors = records["collection-errors.json"]
    provider = Provider(provider_name, "keycloak", provider_name)

    users = _unique_rows(records["users.jsonl"], "users.jsonl")
    groups = _unique_rows(records["groups.jsonl"], "groups.jsonl")
    clients = _unique_rows(records["clients.jsonl"], "clients.jsonl")
    clients_by_id = {_text(row, "id"): row for row in clients}
    realm_roles = _unique_rows(records["realm-roles.jsonl"], "realm-roles.jsonl")
    client_roles = _unique_rows(records["client-roles.jsonl"], "client-roles.jsonl")
    service_rows = _unique_rows(records["service-accounts.jsonl"], "service-accounts.jsonl")
    service_ids = {_text(row, "user_id", "id") for row in service_rows}

    identities: list[Identity] = []
    by_id: dict[str, Identity] = {}
    unresolved: list[dict[str, Any]] = []
    is_full = manifest["completeness"] == "full"
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
    for row in service_rows:
        native_id = _text(row, "user_id", "id")
        if not native_id:
            unresolved.append({"type": "service_account", "reason": "missing_id", "row": row})
            continue
        identity = by_id.get(native_id)
        if identity is None:
            identity = Identity(
                provider_name,
                _text(row, "username", "name") or native_id,
                IdentityType.TECHNICAL_ACCOUNT,
                _status(row),
                native_id=native_id,
                display_name=_text(row, "display_name", "displayName", "username", "name")
                or native_id,
                metadata={"keycloak_realm": realm, "service_account": True},
            )
            identities.append(identity)
            by_id[native_id] = identity
        else:
            identity.type = IdentityType.TECHNICAL_ACCOUNT
            identity.metadata["service_account"] = True
            if row.get("enabled") is False:
                identity.status = IdentityStatus.DISABLED
            if not identity.display_name:
                identity.display_name = _text(row, "username", "name") or native_id
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
        client: dict[str, Any] | None = None,
        resource_identifier: str | None = None,
        description: str | None = None,
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
                    {
                        "realm": realm,
                        "client_id": _text(client or {}, "clientId", "client_id"),
                        "client_native_id": client_id,
                        "client_display_name": _text(client or {}, "name", "clientId"),
                    }
                    if client_id
                    else {"realm": realm}
                ),
            ),
            permission=Permission("member" if kind == "keycloak_group" else "role", display_name),
            target=Target(
                service={"identifier": "Keycloak", "realm": realm},
                component=(
                    {
                        "identifier": client_id,
                        "display_name": _text(client or {}, "name", "clientId") or client_id,
                    }
                    if client_id
                    else {"identifier": "realm", "display_name": realm}
                ),
                resource={
                    "identifier": resource_identifier or native_id,
                    "display_name": display_name,
                },
            ),
            display_name=display_name,
            description=description,
        )
        accesses.append(access_by_key[name])

    for row in groups:
        group_id = _text(row, "id")
        add_access(
            f"group:{group_id}:member",
            group_id,
            "keycloak_group",
            _text(row, "name") or group_id,
            description=_text(row, "description") or None,
        )
    role_access: dict[tuple[str, str, str], str] = {}
    for row in realm_roles + client_roles:
        kind, role_id, client_id = _role_key(row)
        if not role_id:
            unresolved.append({"type": "role", "reason": "missing_id", "row": row})
            continue
        if kind not in {"realm", "client"}:
            raise ValueError(f"Unsupported Keycloak role kind: {kind}")
        if kind == "client" and client_id not in clients_by_id:
            unresolved.append({"type": "client_role", "reason": "missing_client", "row": row})
            continue
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
            clients_by_id.get(client_id) if client_id else None,
            description=_text(row, "description") or None,
        )
        role_access[(kind, role_id, client_id)] = name

    def role_access_for(row: dict[str, Any]) -> str | None:
        return role_access.get(_role_key(row))

    for row in _unique_rows(records["group-memberships.jsonl"], "group-memberships.jsonl"):
        member = by_id.get(_text(row, "member_id", "user_id"))
        group_id = _text(row, "group_id")
        group = by_id.get(group_id)
        if member is None or group is None or group.type != IdentityType.GROUP:
            unresolved.append({"type": "membership", "row": row})
            continue
        access_name = f"group:{group_id}:member"
        assignments.append(
            AccessAssignment(
                provider_name,
                access_name,
                member.provider,
                member.identifier,
                Origin(AssignmentType.GROUP, True, False, group.identifier, dict(row)),
                id=_stable_id("membership", stable_checksum(row)),
            )
        )
        if member.type == IdentityType.GROUP:
            relations.append(
                AccessRelation(
                    provider_name,
                    f"group:{member.native_id}:member",
                    provider_name,
                    access_name,
                    AccessRelationType.GRANTS,
                    Origin(
                        AssignmentType.GROUP,
                        False,
                        True,
                        member.identifier,
                        {"nested_group": True, **row},
                    ),
                    id=_stable_id("nested-group", stable_checksum(row)),
                )
            )

    for filename, identity_key in (
        ("user-role-mappings.jsonl", "user_id"),
        ("group-role-mappings.jsonl", "group_id"),
    ):
        for row in _unique_rows(records[filename], filename):
            role_name = role_access_for(row)
            subject = by_id.get(_text(row, identity_key))
            if role_name is None or subject is None:
                unresolved.append(
                    {
                        "type": "role_mapping",
                        "file": filename,
                        "row": row,
                        "missing": [
                            value
                            for value, absent in (
                                ("subject", subject is None),
                                ("role", role_name is None),
                            )
                            if absent
                        ],
                    }
                )
                continue
            assignments.append(
                AccessAssignment(
                    provider_name,
                    role_name,
                    subject.provider,
                    subject.identifier,
                    Origin(AssignmentType.ROLE, True, False, subject.identifier, dict(row)),
                    id=_stable_id("role-mapping", f"{filename}:{stable_checksum(row)}"),
                )
            )
            if filename == "group-role-mappings.jsonl":
                relations.append(
                    AccessRelation(
                        provider_name,
                        f"group:{subject.native_id}:member",
                        provider_name,
                        role_name,
                        AccessRelationType.GRANTS,
                        Origin(
                            AssignmentType.GROUP,
                            False,
                            True,
                            subject.identifier,
                            {"group_role_mapping": True, **row},
                        ),
                        id=_stable_id("group-role", stable_checksum(row)),
                    )
                )

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
            unresolved.append(
                {
                    "type": "composite",
                    "row": row,
                    "missing": [
                        value
                        for value, absent in (("parent", parent is None), ("child", child is None))
                        if absent
                    ],
                }
            )
            continue
        relations.append(
            AccessRelation(
                provider_name,
                parent,
                provider_name,
                child,
                AccessRelationType.GRANTS,
                Origin(AssignmentType.ROLE, False, True, parent, {"composite": True, **row}),
                id=_stable_id("composite", stable_checksum(row)),
            )
        )

    functional_models, capabilities, permission_capability_mappings = _authorization_models(
        records,
        clients_by_id,
        role_access,
        provider_name,
        realm,
    )

    if unresolved and is_full:
        raise ValueError(
            f"Keycloak artifact contains unresolved structural references: {len(unresolved)}"
        )
    completeness = str(manifest["completeness"])
    if errors or unresolved:
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
    scope["authorization_services"] = manifest.get("authorization_services", {})
    scope["authorization_evidence"] = {
        filename: records[filename] for filename in KEYCLOAK_AUTHZ_FILES if records[filename]
    }
    scope["authorization_complex_permissions"] = _complex_authorization_permissions(records)
    if errors:
        scope["collection_errors"] = errors
    if unresolved:
        scope["unresolved_references"] = unresolved
    checksum_manifest = json.loads(json.dumps(manifest, default=str))
    batch = ImportBatch(
        provider_name,
        "keycloak_zip",
        ImportStatus.COMPLETED,
        completeness,
        scope,
        stable_checksum({"manifest": checksum_manifest, "records": records}),
        completed_at=now_utc(),
    )
    return ImportResult(
        batch,
        provider,
        identities,
        accesses,
        assignments,
        relations,
        functional_access_models=functional_models,
        capabilities=capabilities,
        permission_capability_mappings=permission_capability_mappings,
    )
