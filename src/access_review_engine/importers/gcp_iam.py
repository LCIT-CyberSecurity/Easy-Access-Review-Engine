from __future__ import annotations

import re
from hashlib import sha256

from access_review_engine.domain import (
    Access,
    AccessAssignment,
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
    "iam-bindings.jsonl",
    "service-accounts.jsonl",
    "resource-hierarchy.jsonl",
    "collection-errors.json",
}


def _stable(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _principal(value: str) -> tuple[str, str, str, dict[str, object]]:
    raw = value.strip()
    if raw in {"allUsers", "allAuthenticatedUsers"}:
        return IdentityType.GROUP, raw, raw, {"built_in": True}
    deleted = re.match(r"^deleted:(user|group|serviceAccount):(.+)$", raw)
    if deleted:
        kind, identifier = deleted.groups()
        mapped = {
            "user": IdentityType.USER_ACCOUNT,
            "group": IdentityType.GROUP,
            "serviceAccount": IdentityType.TECHNICAL_ACCOUNT,
        }[kind]
        return mapped, identifier.lower(), kind, {"deleted": True}
    if raw.startswith("principalSet://"):
        return IdentityType.GROUP, raw, "principalSet", {"unresolved": True}
    if raw.startswith("principal://"):
        return IdentityType.TECHNICAL_ACCOUNT, raw, "principal", {"unresolved": True}
    prefix, _, identifier = raw.partition(":")
    mapped = {
        "user": IdentityType.USER_ACCOUNT,
        "group": IdentityType.GROUP,
        "serviceAccount": IdentityType.TECHNICAL_ACCOUNT,
        "domain": IdentityType.GROUP,
    }.get(prefix)
    if mapped:
        return mapped, identifier.lower(), prefix, {}
    return IdentityType.TECHNICAL_ACCOUNT, raw, "unknown", {"unresolved": True}


def import_gcp_iam_zip(
    path: str,
    known_identities: list[Identity] | None = None,
    known_provider_types: dict[str, str] | None = None,
) -> ImportResult:
    manifest, records = read_artifact(path, "gcp_iam", FILES)
    provider_name = str(manifest["provider"])
    provider = Provider(provider_name, "gcp_iam", manifest.get("display_name") or provider_name)
    known: dict[tuple[str, str], list[Identity]] = {}
    for identity in known_identities or []:
        known.setdefault((identity.identifier.lower(), identity.type), []).append(identity)
        for alias in (
            identity.metadata.get("aliases", []) if isinstance(identity.metadata, dict) else []
        ):
            known.setdefault((str(alias).lower(), identity.type), []).append(identity)

    def resolve_known(identifier: str, identity_type: str, preferred_type: str) -> Identity | None:
        candidates = {
            (item.provider, item.identifier): item
            for item in known.get((identifier.lower(), identity_type), [])
        }
        preferred = {
            key: item
            for key, item in candidates.items()
            if (known_provider_types or {}).get(item.provider) == preferred_type
        }
        candidates = preferred or candidates
        return next(iter(candidates.values())) if len(candidates) == 1 else None
    identities: list[Identity] = []
    service_accounts: dict[str, Identity] = {}
    for row in records["service-accounts.jsonl"]:
        email = (
            str(row.get("email") or row.get("name") or "")
            .removeprefix("projects/")
            .split("/serviceAccounts/")[-1]
            .lower()
        )
        if not email:
            raise ValueError("GCP service account is missing email")
        identity = Identity(
            provider_name,
            email,
            IdentityType.TECHNICAL_ACCOUNT,
            IdentityStatus.DISABLED if row.get("disabled") else IdentityStatus.ACTIVE,
            native_id=str(row.get("uniqueId") or row.get("unique_id") or "") or None,
            display_name=row.get("displayName") or email,
            email=email,
            description=row.get("description"),
            metadata={"project": row.get("project")},
        )
        identities.append(identity)
        service_accounts[email] = identity
    accesses: list[Access] = []
    assignments: list[AccessAssignment] = []
    seen: set[str] = set()
    for row in records["iam-bindings.jsonl"]:
        resource = str(row.get("resource") or "").strip()
        role = str(row.get("role") or "").strip()
        condition = row.get("condition") or {}
        expression = (
            condition.get("expression", "") if isinstance(condition, dict) else str(condition)
        )
        if not resource or not role:
            raise ValueError("GCP IAM binding requires resource and role")
        semantic = f"{resource}\n{role}\n{expression}"
        name = f"gcp-iam:{_stable(semantic)}"
        if name not in seen:
            seen.add(name)
            accesses.append(
                Access(
                    name,
                    provider_name,
                    ControlObject(
                        type="gcp_iam_binding",
                        identifier=f"gcp-iam-binding:{_stable(semantic)}",
                        native_id=f"gcp-iam-binding:{_stable(semantic)}",
                        display_name=role,
                        description=None,
                        metadata={
                            "resource": resource,
                            "role": role,
                            "condition": condition,
                        },
                    ),
                    Permission(role, role, metadata={"condition": condition} if condition else {}),
                    Target(
                        service={"identifier": "Google Cloud"},
                        component={"identifier": "IAM"},
                        resource={"identifier": resource},
                    ),
                    display_name=f"{role} — {resource}",
                    metadata={"resource": resource, "role": role, "condition": condition},
                )
            )
        for raw_member in row.get("members") or []:
            member = str(raw_member)
            kind, identifier, prefix, principal_metadata = _principal(member)
            resolved: Identity | None = None
            if prefix == "serviceAccount":
                resolved = service_accounts.get(identifier) or resolve_known(
                    identifier, IdentityType.TECHNICAL_ACCOUNT, "gcp_iam"
                )
            elif prefix in {"user", "group", "domain"}:
                resolved = resolve_known(identifier, kind, "google_workspace")
            unresolved = resolved is None and not bool(principal_metadata.get("built_in"))
            if resolved:
                identity_provider, identity_identifier = resolved.provider, resolved.identifier
            else:
                identity_provider, identity_identifier = provider_name, identifier
                if not any(
                    i.provider == provider_name and i.identifier == identifier for i in identities
                ):
                    identities.append(
                        Identity(
                            provider_name,
                            identifier,
                            kind,
                            IdentityStatus.DELETED
                            if principal_metadata.get("deleted")
                            else IdentityStatus.ACTIVE
                            if principal_metadata.get("built_in")
                            else IdentityStatus.UNKNOWN,
                            built_in=bool(principal_metadata.get("built_in")),
                            metadata={
                                **({"unresolved": True} if unresolved else {}),
                                "principal": member,
                                "principal_type": prefix,
                                **principal_metadata,
                            },
                        )
                    )
            assignments.append(
                AccessAssignment(
                    provider_name,
                    name,
                    identity_provider,
                    identity_identifier,
                    Origin(
                        AssignmentType.POLICY,
                        True,
                        False,
                        resource,
                        {
                            "principal": member,
                            "unresolved": unresolved,
                            "condition": condition,
                        },
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
        manifest.get("authoritative_scope")
        or {
            "connector_type": "gcp_iam",
            "scope": str(manifest.get("scope") or ""),
            "surfaces": sorted(str(item) for item in manifest.get("requested_surfaces", [])),
        }
    )
    scope["completeness"] = completeness
    if errors:
        scope["collection_errors"] = len(errors)
    batch = ImportBatch(
        provider_name,
        "gcp_iam_zip",
        ImportStatus.COMPLETED,
        completeness,
        scope,
        stable_checksum({"manifest": manifest, "records": records}),
        completed_at=now_utc(),
    )
    return ImportResult(batch, provider, identities, accesses, assignments, [])
