from __future__ import annotations

import csv
from dataclasses import dataclass
from io import TextIOWrapper
from pathlib import Path
from zipfile import BadZipFile, ZipFile

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
    ProviderType,
    stable_checksum,
)

ALLOWED_AD_FILES = {"manifest.yaml", "users.csv", "groups.csv", "memberships.csv"}


@dataclass
class ImportResult:
    batch: ImportBatch
    provider: Provider
    identities: list[Identity]
    accesses: list[Access]
    assignments: list[AccessAssignment]


def import_ad_zip(path: str | Path, max_size_bytes: int = 50_000_000) -> ImportResult:
    archive = Path(path)
    if archive.stat().st_size > max_size_bytes:
        raise ValueError("Import archive exceeds configured maximum size")
    try:
        with ZipFile(archive) as zf:
            names = set(zf.namelist())
            if any(name.startswith("/") or ".." in Path(name).parts for name in names):
                raise ValueError("Unsafe ZIP path detected")
            if not ALLOWED_AD_FILES.issuperset(names):
                raise ValueError("Archive contains unexpected files")
            missing = ALLOWED_AD_FILES - names
            if missing:
                raise ValueError(f"Archive is missing required files: {sorted(missing)}")
            manifest = _read_manifest(zf.read("manifest.yaml").decode("utf-8"))
            provider_name = manifest.get("provider") or manifest.get("provider_name")
            if not provider_name:
                raise ValueError("manifest.yaml must define provider")
            users = list(_read_csv(zf, "users.csv"))
            groups = list(_read_csv(zf, "groups.csv"))
            memberships = list(_read_csv(zf, "memberships.csv"))
    except BadZipFile as exc:
        raise ValueError("Invalid ZIP archive") from exc

    provider = Provider(
        name=str(provider_name),
        type=ProviderType.ACTIVE_DIRECTORY,
        display_name=str(manifest.get("display_name") or provider_name),
        description=manifest.get("description"),
    )
    identities = [_user_identity(provider.name, row) for row in users]
    identities.extend(_group_identity(provider.name, row) for row in groups)
    group_by_sid = {identity.native_id: identity for identity in identities if identity.type == IdentityType.GROUP}
    group_by_name = {identity.identifier: identity for identity in identities if identity.type == IdentityType.GROUP}
    accesses: list[Access] = []
    assignments: list[AccessAssignment] = []
    seen_accesses: set[str] = set()
    for row in memberships:
        group_id = row.get("GroupSID") or row.get("Group")
        group = group_by_sid.get(group_id) or group_by_name.get(row.get("Group", ""))
        if group is None:
            continue
        access_name = f"{group.identifier}:member"
        if access_name not in seen_accesses:
            accesses.append(
                Access(
                    name=access_name,
                    provider=provider.name,
                    control_object=ControlObject(
                        type="group",
                        identifier=group.identifier,
                        native_id=group.native_id,
                        display_name=group.display_name,
                        description=group.description,
                    ),
                    permission=Permission(identifier="member", display_name="Member"),
                    description=group.description,
                )
            )
            seen_accesses.add(access_name)
        member_identifier = row.get("Member") or row.get("MemberSID")
        if not member_identifier:
            continue
        assignments.append(
            AccessAssignment(
                provider=provider.name,
                access_name=access_name,
                identity_provider=provider.name,
                identity_identifier=member_identifier,
                origin=Origin(
                    assignment_type=AssignmentType.GROUP,
                    direct=True,
                    inherited=False,
                    source=group.identifier,
                    raw={key: value for key, value in row.items() if value},
                ),
            )
        )
    checksum = stable_checksum({"users": users, "groups": groups, "memberships": memberships})
    batch = ImportBatch(
        provider=provider.name,
        source_type="active_directory_zip",
        status=ImportStatus.COMPLETED,
        completeness=str(manifest.get("completeness") or Completeness.FULL),
        scope=manifest.get("scope") if isinstance(manifest.get("scope"), dict) else {"type": "all"},
        checksum=checksum,
    )
    from access_review_engine.domain import now_utc

    batch.completed_at = now_utc()
    return ImportResult(batch, provider, identities, accesses, assignments)


def _read_manifest(text: str) -> dict[str, object]:
    result: dict[str, object] = {}
    for line in text.splitlines():
        if not line.strip() or line.strip().startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        result[key.strip()] = value.strip().strip("\"'")
    return result


def _read_csv(zf: ZipFile, name: str) -> list[dict[str, str]]:
    with zf.open(name) as raw:
        reader = csv.DictReader(TextIOWrapper(raw, encoding="utf-8-sig", newline=""))
        return [{key: value for key, value in row.items()} for row in reader]


def _user_identity(provider: str, row: dict[str, str]) -> Identity:
    return Identity(
        provider=provider,
        identifier=row["SamAccountName"],
        native_id=row.get("SID") or None,
        type=IdentityType.USER_ACCOUNT,
        status=IdentityStatus.ACTIVE if _truthy(row.get("Enabled")) else IdentityStatus.DISABLED,
        display_name=row.get("DisplayName") or row.get("SamAccountName"),
        email=row.get("Mail") or None,
        description=row.get("Description") or None,
        metadata={
            "user_principal_name": row.get("UserPrincipalName"),
            "distinguished_name": row.get("DistinguishedName"),
            "last_logon_date": row.get("LastLogonDate"),
            "password_last_set": row.get("PasswordLastSet"),
            "account_expiration_date": row.get("AccountExpirationDate"),
            "when_created": row.get("WhenCreated"),
        },
    )


def _group_identity(provider: str, row: dict[str, str]) -> Identity:
    return Identity(
        provider=provider,
        identifier=row["SamAccountName"],
        native_id=row.get("SID") or None,
        type=IdentityType.GROUP,
        status=IdentityStatus.ACTIVE,
        display_name=row.get("Name") or row.get("SamAccountName"),
        description=row.get("Description") or None,
        metadata={
            "distinguished_name": row.get("DistinguishedName"),
            "group_scope": row.get("GroupScope"),
            "group_category": row.get("GroupCategory"),
        },
    )


def _truthy(value: str | None) -> bool:
    return str(value).lower() in {"1", "true", "yes", "y", "enabled"}
