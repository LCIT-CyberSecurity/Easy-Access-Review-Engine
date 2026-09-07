from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import UTC, datetime
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

REQUIRED_AD_FILES = {"manifest.yaml", "users.csv", "groups.csv", "memberships.csv"}
OPTIONAL_AD_FILES = {"service_accounts.csv", "computers.csv", "collection-errors.csv"}
ALLOWED_AD_FILES = REQUIRED_AD_FILES | OPTIONAL_AD_FILES
MAX_AD_ZIP_FILES = 16
DEFAULT_AD_ARCHIVE_BYTES = 500_000_000
DEFAULT_AD_FILE_BYTES = 250_000_000
DEFAULT_AD_MEMBERSHIPS_FILE_BYTES = 1_000_000_000
DEFAULT_AD_UNCOMPRESSED_BYTES = 1_500_000_000
SUPPORTED_SCHEMA_VERSIONS = {1}
SUPPORTED_COMPLETENESS = {Completeness.FULL, Completeness.SCOPED, Completeness.UNKNOWN}
BUILT_IN_ACCOUNT_RIDS = {"500", "501", "502"}
MANAGED_SERVICE_ACCOUNT_CLASSES = {
    "msds-managedserviceaccount": "msa",
    "msds-groupmanagedserviceaccount": "gmsa",
}
KNOWN_MEMBER_TYPES = {
    "user",
    "group",
    "computer",
    "msds-managedserviceaccount",
    "msds-groupmanagedserviceaccount",
    "foreignsecurityprincipal",
}


@dataclass
class ImportResult:
    batch: ImportBatch
    provider: Provider
    identities: list[Identity]
    accesses: list[Access]
    assignments: list[AccessAssignment]


def import_ad_zip(
    path: str | Path,
    max_size_bytes: int = DEFAULT_AD_ARCHIVE_BYTES,
    known_identities: list[Identity] | None = None,
    max_file_bytes: int = DEFAULT_AD_FILE_BYTES,
    max_memberships_file_bytes: int = DEFAULT_AD_MEMBERSHIPS_FILE_BYTES,
    max_uncompressed_bytes: int = DEFAULT_AD_UNCOMPRESSED_BYTES,
    classification_rules: dict[str, object] | None = None,
) -> ImportResult:
    archive = Path(path)
    if archive.stat().st_size > max_size_bytes:
        raise ValueError("Import archive exceeds configured maximum size")
    try:
        with ZipFile(archive) as zf:
            names = zf.namelist()
            unique_names = set(names)
            if len(names) != len(unique_names):
                raise ValueError("Archive contains duplicate filenames")
            if len(names) > MAX_AD_ZIP_FILES:
                raise ValueError("Archive contains too many files")
            if any(name.startswith("/") or ".." in Path(name).parts for name in names):
                raise ValueError("Unsafe ZIP path detected")
            if not ALLOWED_AD_FILES.issuperset(unique_names):
                raise ValueError("Archive contains unexpected files")
            _validate_zip_members(
                zf,
                max_file_bytes=max_file_bytes,
                max_memberships_file_bytes=max_memberships_file_bytes,
                max_uncompressed_bytes=max_uncompressed_bytes,
            )
            missing = REQUIRED_AD_FILES - unique_names
            if missing:
                raise ValueError(f"Archive is missing required files: {sorted(missing)}")
            manifest = _read_manifest(zf.read("manifest.yaml").decode("utf-8-sig"))
            _validate_manifest(manifest)
            provider_name = manifest.get("provider") or manifest.get("provider_name")
            if not provider_name:
                raise ValueError("manifest.yaml must define provider")
            users = _read_csv(zf, "users.csv")
            groups = _read_csv(zf, "groups.csv")
            memberships = _read_csv(zf, "memberships.csv")
            service_accounts = _read_csv(zf, "service_accounts.csv") if "service_accounts.csv" in unique_names else []
            computers = _read_csv(zf, "computers.csv") if "computers.csv" in unique_names else []
            collection_errors = (
                _read_csv(zf, "collection-errors.csv") if "collection-errors.csv" in unique_names else []
            )
    except BadZipFile as exc:
        raise ValueError("Invalid ZIP archive") from exc

    provider = Provider(
        name=str(provider_name),
        type=ProviderType.ACTIVE_DIRECTORY,
        display_name=str(manifest.get("display_name") or provider_name),
        description=manifest.get("description"),
    )
    rules = classification_rules or {}
    identities = [_user_identity(provider.name, row, rules) for row in users]
    identities.extend(_service_account_identity(provider.name, row) for row in service_accounts)
    identities.extend(_computer_identity(provider.name, row) for row in computers)
    identities.extend(_group_identity(provider.name, row) for row in groups)

    identity_by_sid = {identity.native_id: identity for identity in identities if identity.native_id}
    global_by_sid = _global_identity_index([*(known_identities or []), *identities])
    group_by_sid = {identity.native_id: identity for identity in identities if identity.type == IdentityType.GROUP}
    group_by_name = {identity.identifier: identity for identity in identities if identity.type == IdentityType.GROUP}

    accesses: list[Access] = []
    assignments: list[AccessAssignment] = []
    seen_accesses: set[str] = set()
    seen_assignments: set[tuple[str, str, str, str, str]] = set()
    for row in memberships:
        group_id = row.get("GroupSID") or row.get("Group")
        group = group_by_sid.get(group_id) or group_by_name.get(row.get("Group", ""))
        if group is None:
            continue
        access_name = f"{group.identifier}:member"
        if access_name not in seen_accesses:
            accesses.append(_group_access(provider.name, group))
            seen_accesses.add(access_name)
        member_provider, member_identifier, raw_flags = _resolve_member(provider.name, row, identity_by_sid, global_by_sid)
        if not member_identifier:
            continue
        membership_type = row.get("MembershipType") or "direct"
        assignment_type = "primary_group" if membership_type == "primary_group" else AssignmentType.GROUP
        raw = {key: value for key, value in row.items() if value}
        raw.update(raw_flags)
        fingerprint_key = (provider.name, access_name, member_provider, member_identifier, stable_checksum(raw))
        if fingerprint_key in seen_assignments:
            continue
        seen_assignments.add(fingerprint_key)
        assignments.append(
            AccessAssignment(
                provider=provider.name,
                access_name=access_name,
                identity_provider=member_provider,
                identity_identifier=member_identifier,
                origin=Origin(
                    assignment_type=assignment_type,
                    direct=True,
                    inherited=False,
                    source=group.identifier,
                    raw=raw,
                ),
            )
        )

    _validate_collection_error_count(manifest, len(collection_errors))
    completeness = _effective_completeness(manifest, collection_errors)
    checksum = stable_checksum(
        {
            "manifest": manifest,
            "users": users,
            "groups": groups,
            "service_accounts": service_accounts,
            "computers": computers,
            "memberships": memberships,
            "collection_errors": collection_errors,
        }
    )
    batch = ImportBatch(
        provider=provider.name,
        source_type="active_directory_zip",
        status=ImportStatus.COMPLETED,
        completeness=completeness,
        scope=_effective_scope(manifest, completeness),
        checksum=checksum,
    )
    batch.scope["completeness"] = completeness
    if collection_errors:
        batch.scope["collection_errors"] = len(collection_errors)
    from access_review_engine.domain import now_utc

    batch.completed_at = now_utc()
    return ImportResult(batch, provider, identities, accesses, assignments)


def _validate_zip_members(
    zf: ZipFile,
    max_file_bytes: int,
    max_memberships_file_bytes: int,
    max_uncompressed_bytes: int,
) -> None:
    total = 0
    for info in zf.infolist():
        member_limit = max_memberships_file_bytes if info.filename == "memberships.csv" else max_file_bytes
        if info.file_size > member_limit:
            raise ValueError("Archive member exceeds configured maximum size")
        total += info.file_size
        if total > max_uncompressed_bytes:
            raise ValueError("Archive uncompressed size exceeds configured maximum size")


def _validate_manifest(manifest: dict[str, object]) -> None:
    schema_version = manifest.get("schema_version")
    if schema_version is not None and schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise ValueError("manifest.yaml has unsupported schema_version")
    source_type = manifest.get("source_type")
    if source_type is not None and source_type != "active_directory":
        raise ValueError("manifest.yaml has unsupported source_type")
    completeness = manifest.get("completeness")
    if completeness is not None and completeness not in SUPPORTED_COMPLETENESS:
        raise ValueError("manifest.yaml has unsupported completeness")
    scope = manifest.get("scope")
    if isinstance(scope, dict):
        scope_completeness = scope.get("completeness")
        if scope_completeness is not None and scope_completeness not in SUPPORTED_COMPLETENESS:
            raise ValueError("manifest.yaml scope.completeness has unsupported completeness")


def _effective_completeness(manifest: dict[str, object], collection_errors: list[dict[str, str]]) -> str:
    values = [str(manifest.get("completeness") or Completeness.UNKNOWN)]
    scope = manifest.get("scope")
    if isinstance(scope, dict) and scope.get("completeness") is not None:
        values.append(str(scope["completeness"]))
    if collection_errors:
        values.append(str(Completeness.UNKNOWN))
    precedence = {str(Completeness.UNKNOWN): 0, str(Completeness.SCOPED): 1, str(Completeness.FULL): 2}
    return min(values, key=lambda value: precedence.get(value, 0))


def _effective_scope(manifest: dict[str, object], completeness: str) -> dict[str, object]:
    scope = manifest.get("scope")
    effective = dict(scope) if isinstance(scope, dict) else {"type": "all"}
    effective["completeness"] = completeness
    return effective


def _validate_collection_error_count(manifest: dict[str, object], actual_errors: int) -> None:
    stats = manifest.get("statistics")
    if not isinstance(stats, dict) or "collection_errors" not in stats:
        return
    declared = stats["collection_errors"]
    if not isinstance(declared, int):
        raise ValueError("manifest.yaml statistics.collection_errors must be an integer")
    if declared != actual_errors:
        raise ValueError("manifest.yaml collection_errors does not match collection-errors.csv")


def _read_manifest(text: str) -> dict[str, object]:
    result: dict[str, object] = {}
    stack: list[str] = []
    for line in text.splitlines():
        if not line.strip() or line.strip().startswith("#") or ":" not in line:
            continue
        indent = len(line) - len(line.lstrip(" "))
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        if indent == 0:
            stack = [key]
            result[key] = {} if value == "" else _manifest_value(value)
        elif stack:
            parent = result.setdefault(stack[0], {})
            if isinstance(parent, dict):
                parent[key] = _manifest_value(value)
    return result


def _manifest_value(value: str) -> object:
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    if value.isdigit():
        return int(value)
    return value


def _read_csv(zf: ZipFile, name: str) -> list[dict[str, str]]:
    with zf.open(name) as raw:
        reader = csv.DictReader(TextIOWrapper(raw, encoding="utf-8-sig", newline=""))
        if reader.fieldnames is None:
            return []
        return [{key: value for key, value in row.items()} for row in reader]


def _user_identity(provider: str, row: dict[str, str], rules: dict[str, object]) -> Identity:
    identity_type = _classify_user(row, rules)
    sid = row.get("SID") or None
    return Identity(
        provider=provider,
        identifier=row["SamAccountName"],
        native_id=sid,
        type=identity_type,
        status=_enabled_status(row),
        display_name=row.get("DisplayName") or row.get("SamAccountName"),
        email=row.get("Mail") or None,
        description=row.get("Description") or None,
        built_in=_is_builtin_sid(sid),
        metadata={
            "principal_kind": "user",
            "user_principal_name": row.get("UserPrincipalName") or None,
            "distinguished_name": row.get("DistinguishedName") or None,
            "last_logon_date": row.get("LastLogonDate") or None,
            "password_last_set": row.get("PasswordLastSet") or None,
            "account_expiration_date": row.get("AccountExpirationDate") or None,
            "account_expired": _is_past_datetime(row.get("AccountExpirationDate")),
            "when_created": row.get("WhenCreated") or None,
            "primary_group_id": row.get("PrimaryGroupID") or None,
            "locked_out": _truthy(row.get("LockedOut")),
            "service_principal_name": row.get("ServicePrincipalName") or None,
            "object_guid": row.get("ObjectGUID") or None,
        },
    )


def _service_account_identity(provider: str, row: dict[str, str]) -> Identity:
    object_class = (row.get("ObjectClass") or "").lower()
    return Identity(
        provider=provider,
        identifier=row["SamAccountName"],
        native_id=row.get("SID") or None,
        type=IdentityType.TECHNICAL_ACCOUNT,
        status=_enabled_status(row),
        display_name=row.get("Name") or row.get("DisplayName") or row.get("SamAccountName"),
        description=row.get("Description") or None,
        metadata={
            "principal_kind": "managed_service_account",
            "managed_service_account_type": MANAGED_SERVICE_ACCOUNT_CLASSES.get(object_class, "msa"),
            "distinguished_name": row.get("DistinguishedName") or None,
            "service_principal_name": row.get("ServicePrincipalName") or None,
            "primary_group_id": row.get("PrimaryGroupID") or None,
            "object_class": row.get("ObjectClass") or None,
            "object_guid": row.get("ObjectGUID") or None,
        },
    )


def _computer_identity(provider: str, row: dict[str, str]) -> Identity:
    return Identity(
        provider=provider,
        identifier=row["SamAccountName"],
        native_id=row.get("SID") or None,
        type=IdentityType.TECHNICAL_ACCOUNT,
        status=_enabled_status(row),
        display_name=row.get("Name") or row.get("SamAccountName"),
        description=row.get("Description") or None,
        metadata={
            "principal_kind": "computer",
            "distinguished_name": row.get("DistinguishedName") or None,
            "dns_host_name": row.get("DNSHostName") or None,
            "primary_group_id": row.get("PrimaryGroupID") or None,
            "object_guid": row.get("ObjectGUID") or None,
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
        built_in=_is_builtin_sid(row.get("SID")),
        metadata={
            "distinguished_name": row.get("DistinguishedName") or None,
            "group_scope": row.get("GroupScope") or None,
            "group_category": row.get("GroupCategory") or None,
        },
    )


def _group_access(provider: str, group: Identity) -> Access:
    return Access(
        name=f"{group.identifier}:member",
        provider=provider,
        control_object=ControlObject(
            type="group",
            identifier=group.identifier,
            native_id=group.native_id,
            display_name=group.display_name,
            description=group.description,
            metadata={
                "group_scope": group.metadata.get("group_scope"),
                "group_category": group.metadata.get("group_category"),
            },
        ),
        permission=Permission(identifier="member", display_name="Member"),
        description=group.description,
    )


def _resolve_member(
    current_provider: str,
    row: dict[str, str],
    local_by_sid: dict[str, Identity],
    global_by_sid: dict[str, Identity | None],
) -> tuple[str, str, dict[str, object]]:
    member_sid = row.get("MemberSID") or None
    member_type = (row.get("MemberType") or "unknown").lower()
    raw_flags: dict[str, object] = {
        "member_sid": member_sid,
        "member_dn": row.get("MemberDN") or None,
        "member_type": row.get("MemberType") or None,
        "membership_type": row.get("MembershipType") or "direct",
    }
    if member_type not in KNOWN_MEMBER_TYPES:
        raw_flags["unresolved"] = True
        raw_flags["unknown_member_type"] = True
    if member_sid:
        local = local_by_sid.get(member_sid)
        if local is not None:
            return local.provider, local.identifier, raw_flags
        global_match = global_by_sid.get(member_sid)
        if global_match is not None:
            raw_flags["cross_domain_resolved"] = global_match.provider != current_provider
            return global_match.provider, global_match.identifier, raw_flags
    member = row.get("Member") or member_sid or ""
    if member_type == "foreignsecurityprincipal" or member_sid:
        raw_flags["unresolved"] = True
        if member_type == "foreignsecurityprincipal":
            raw_flags["unresolved_foreign_principal"] = True
        return "", member_sid or member, raw_flags
    return current_provider, member, raw_flags


def _global_identity_index(identities: list[Identity]) -> dict[str, Identity | None]:
    by_sid: dict[str, Identity | None] = {}
    for identity in identities:
        if not identity.native_id:
            continue
        if identity.native_id in by_sid:
            by_sid[identity.native_id] = None
        else:
            by_sid[identity.native_id] = identity
    return by_sid


def _classify_user(row: dict[str, str], rules: dict[str, object]) -> str:
    shared = rules.get("shared_account") if isinstance(rules.get("shared_account"), dict) else {}
    technical = rules.get("technical_account") if isinstance(rules.get("technical_account"), dict) else {}
    sam = row.get("SamAccountName", "")
    dn = row.get("DistinguishedName", "")
    if _matches_account_rules(row, sam, dn, shared):
        return IdentityType.SHARED_ACCOUNT
    if _matches_account_rules(row, sam, dn, technical):
        return IdentityType.TECHNICAL_ACCOUNT
    return IdentityType.USER_ACCOUNT


def _matches_account_rules(row: dict[str, str], sam: str, dn: str, rules: object) -> bool:
    if not isinstance(rules, dict):
        return False
    prefixes = rules.get("samaccountname_prefixes", [])
    if isinstance(prefixes, list) and any(sam.lower().startswith(str(prefix).lower()) for prefix in prefixes):
        return True
    dn_contains = rules.get("dn_contains", [])
    if isinstance(dn_contains, list) and any(str(part).lower() in dn.lower() for part in dn_contains):
        return True
    return bool(rules.get("has_service_principal_name") and row.get("ServicePrincipalName"))


def _is_builtin_sid(sid: str | None) -> bool:
    if not sid:
        return False
    if sid.startswith("S-1-5-32-"):
        return True
    return sid.rsplit("-", 1)[-1] in BUILT_IN_ACCOUNT_RIDS


def _is_past_datetime(value: str | None) -> bool:
    if not value:
        return False
    normalized = value.strip()
    for fmt in (None, "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%m/%d/%Y %I:%M:%S %p"):
        try:
            dt = datetime.fromisoformat(normalized.replace("Z", "+00:00")) if fmt is None else datetime.strptime(normalized, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt < datetime.now(UTC)
        except ValueError:
            continue
    return False


def _enabled_status(row: dict[str, str]) -> str:
    value = row.get("Enabled")
    if value is None or not str(value).strip():
        return IdentityStatus.UNKNOWN
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "y"}:
        return IdentityStatus.ACTIVE
    if normalized in {"0", "false", "no", "n"}:
        return IdentityStatus.DISABLED
    return IdentityStatus.UNKNOWN


def _truthy(value: str | None) -> bool:
    return str(value).lower() in {"1", "true", "yes", "y", "enabled"}
