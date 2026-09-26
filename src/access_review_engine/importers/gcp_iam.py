from __future__ import annotations

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


def _principal(value: str) -> tuple[str, str, str]:
    prefix, _, identifier = value.partition(":")
    if prefix == "user":
        return "user_account", identifier.lower(), "user"
    if prefix == "group":
        return "group", identifier.lower(), "group"
    if prefix == "serviceAccount":
        return "technical_account", identifier.lower(), "serviceAccount"
    return "unknown", value, prefix


def import_gcp_iam_zip(path: str, known_identities: list[Identity] | None = None) -> ImportResult:
    manifest, records = read_artifact(path, "gcp_iam", FILES)
    provider_name = str(manifest["provider"])
    provider = Provider(provider_name, "gcp_iam", manifest.get("display_name") or provider_name)
    known = {
        (identity.identifier.lower(), identity.type): identity
        for identity in (known_identities or [])
    }
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
                        "gcp_iam_binding",
                        f"{resource}|{role}|{_stable(expression)}",
                        None,
                        role,
                        {"condition": condition} if condition else {},
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
            kind, identifier, prefix = _principal(member)
            resolved: Identity | None = None
            if prefix == "serviceAccount":
                resolved = service_accounts.get(identifier) or known.get(
                    (identifier, IdentityType.TECHNICAL_ACCOUNT)
                )
            elif prefix in {"user", "group"}:
                resolved = known.get((identifier, kind)) or known.get(
                    (
                        identifier,
                        IdentityType.USER_ACCOUNT if prefix == "user" else IdentityType.GROUP,
                    )
                )
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
                            IdentityStatus.UNKNOWN,
                            built_in=prefix in {"allUsers", "allAuthenticatedUsers"},
                            metadata={"unresolved": True, "principal": member},
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
                            "unresolved": resolved is None,
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
        manifest.get("authoritative_scope") or {"type": "providers", "values": [provider_name]}
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
