from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Iterable
from zipfile import BadZipFile, ZipFile

from access_review_engine.domain import (
    Access,
    AccessAssignment,
    Completeness,
    GoldenSourceVersion,
    Identity,
    Provider,
    ProviderType,
)
from access_review_engine.importers.ad import ImportResult, import_ad_zip
from access_review_engine.importers.openldap import (
    DEFAULT_OPENLDAP_FILTER,
    _canonical_dn,
    import_openldap_ldif,
    import_openldap_zip,
)
from access_review_engine.services import create_snapshot, reconcile_identities
from access_review_engine.storage import (
    Repository,
    hydrate_access,
    hydrate_assignment,
    hydrate_identity,
    hydrate_provider,
)


def import_file_to_repository(
    repo: Repository,
    path: str | Path,
    provider_name: str = "openldap",
    golden_version: GoldenSourceVersion | None = None,
    classification_rules: dict[str, object] | None = None,
):
    file_path = Path(path)
    known_identities = _load_identities(repo)
    if file_path.suffix.lower() == ".zip":
        source_type = _zip_source_type(file_path)
        if source_type == "active_directory":
            result = import_ad_zip(
                file_path,
                known_identities=known_identities,
                classification_rules=classification_rules,
            )
        elif source_type == "openldap":
            result = import_openldap_zip(file_path)
        else:
            raise ValueError(f"Unsupported ZIP source_type: {source_type or 'missing'}")
    else:
        result = import_openldap_ldif(file_path, provider_name)
    return persist_import_result(repo, result, golden_version=golden_version)


def persist_import_result(
    repo: Repository,
    result: ImportResult,
    golden_version: GoldenSourceVersion | None = None,
):
    existing_provider_payload = repo.find_by_name("providers", result.provider.name)
    if existing_provider_payload is not None:
        existing_provider = hydrate_provider(existing_provider_payload)
        result.provider.id = existing_provider.id
        result.provider.created_at = existing_provider.created_at

    previous_import_scopes = [
        row.get("scope", {}) for row in repo.list_payloads_by_provider("imports", result.provider.name)
    ]
    result.batch.scope = _provider_import_scope(
        result.provider.name,
        result.provider.type,
        result.batch.scope,
        previous_import_scopes,
    )
    result.batch.completeness = str(
        result.batch.scope.get("completeness", result.batch.completeness)
    )
    authoritative = _is_authoritative_full(result)
    if not authoritative:
        _retain_non_authoritative_unresolved(result)

    repo.upsert("providers", result.provider)
    repo.insert_append_only("imports", result.batch)

    existing_identities = _load_identities(repo, result.provider.name)
    imported_identities = _dedupe_identities(result.identities)
    merged_identities = reconcile_identities(
        existing_identities,
        imported_identities,
        completeness=result.batch.completeness,
        scope=result.batch.scope,
        authoritative=authoritative,
    )
    for identity in sorted(merged_identities, key=lambda item: item.status != "deleted"):
        repo.upsert("identities", identity)

    accesses = _reconcile_accesses(_load_accesses(repo, result.provider.name), result.accesses)
    for access in accesses:
        repo.upsert("accesses", access)

    snapshot_assignments = list(result.assignments)
    if authoritative:
        assignments = _reconcile_assignments(
            _load_assignments(repo, result.provider.name),
            result.assignments,
        )
        repo.replace_assignments(assignments, providers={result.provider.name})
        snapshot_assignments = assignments

    _resolve_unresolved_assignments(repo)

    snapshot = create_snapshot(
        [result.provider],
        _load_identities(repo),
        [],
        _load_accesses(repo),
        snapshot_assignments,
        [result.batch.id],
        golden_version,
        result.batch.scope,
    )
    repo.insert_append_only("snapshots", snapshot)
    return snapshot


def _is_authoritative_full(result: ImportResult) -> bool:
    scope = result.batch.scope or {}
    if (
        result.provider.type == ProviderType.OPENLDAP
        and not _matches_openldap_authoritative_scope(scope)
    ):
        return False
    return (
        result.batch.completeness == Completeness.FULL
        and scope.get("completeness") in {None, Completeness.FULL, "full"}
        and scope.get("type") == "providers"
        and result.provider.name in set(scope.get("values", []))
        and not scope.get("collection_errors")
    )


def _provider_import_scope(
    provider: str,
    provider_type: str,
    scope: dict[str, object] | None,
    previous_scopes: Iterable[dict[str, object]] = (),
) -> dict[str, object]:
    source = dict(scope or {})
    completeness = str(source.get("completeness") or Completeness.UNKNOWN)
    if source.get("type", "all") == "all":
        source["type"] = "providers"
        source["values"] = [provider]
    source.setdefault("provider", provider)
    source["completeness"] = completeness

    if provider_type == ProviderType.OPENLDAP:
        _apply_openldap_authoritative_scope(source, previous_scopes)
    return source


def _apply_openldap_authoritative_scope(
    scope: dict[str, object], previous_scopes: Iterable[dict[str, object]]
) -> None:
    expected = _configured_openldap_authoritative_scope(scope, previous_scopes)
    if expected is None:
        return
    scope["authoritative_scope"] = expected
    current = _canonical_openldap_scope(scope)
    if current != expected and scope.get("completeness") == str(Completeness.FULL):
        scope["completeness"] = str(Completeness.SCOPED)


def _configured_openldap_authoritative_scope(
    scope: dict[str, object], previous_scopes: Iterable[dict[str, object]]
) -> dict[str, str] | None:
    declared = scope.get("authoritative_scope")
    if isinstance(declared, dict):
        return _canonical_openldap_scope(declared)
    for previous in reversed(list(previous_scopes)):
        previous_declared = (
            previous.get("authoritative_scope") if isinstance(previous, dict) else None
        )
        if isinstance(previous_declared, dict):
            return _canonical_openldap_scope(previous_declared)
    if (
        scope.get("completeness") == str(Completeness.FULL)
        and _supported_openldap_authoritative_candidate(scope)
    ):
        return _canonical_openldap_scope(scope)
    return None


def _matches_openldap_authoritative_scope(scope: dict[str, object]) -> bool:
    expected = scope.get("authoritative_scope")
    return (
        isinstance(expected, dict)
        and _canonical_openldap_scope(scope) == _canonical_openldap_scope(expected)
    )


def _supported_openldap_authoritative_candidate(scope: dict[str, object]) -> bool:
    canonical = _canonical_openldap_scope(scope)
    return (
        bool(canonical["base_dn"])
        and canonical["search_scope"] == "sub"
        and canonical["filter"] in {
            "".join(DEFAULT_OPENLDAP_FILTER.split()).lower(),
            "(objectclass=*)",
            "objectclass=*",
        }
    )


def _canonical_openldap_scope(scope: dict[str, object]) -> dict[str, str]:
    base_dn = str(scope.get("base_dn") or "").strip()
    return {
        "base_dn": _canonical_dn(base_dn) if base_dn else "",
        "search_scope": str(scope.get("search_scope") or "sub").strip().lower(),
        "filter": "".join(str(scope.get("filter") or "").split()).lower(),
    }


def _load_identities(repo: Repository, provider: str | None = None) -> list[Identity]:
    rows = (
        repo.list_payloads_by_provider("identities", provider)
        if provider
        else repo.list_payloads("identities")
    )
    return [hydrate_identity(row) for row in rows]


def _load_accesses(repo: Repository, provider: str | None = None) -> list[Access]:
    rows = (
        repo.list_payloads_by_provider("accesses", provider)
        if provider
        else repo.list_payloads("accesses")
    )
    return [hydrate_access(row) for row in rows]


def _load_assignments(repo: Repository, provider: str | None = None) -> list[AccessAssignment]:
    rows = (
        repo.list_payloads_by_provider("access_assignments", provider)
        if provider
        else repo.list_payloads("access_assignments")
    )
    return [hydrate_assignment(row) for row in rows]


def _dedupe_identities(identities: Iterable[Identity]) -> list[Identity]:
    by_key: dict[tuple[str, str], Identity] = {}
    by_native: dict[tuple[str, str], Identity] = {}
    for identity in identities:
        if identity.native_id:
            native_key = (identity.provider, identity.native_id)
            if native_key in by_native:
                previous = by_native[native_key]
                by_key.pop((previous.provider, previous.identifier), None)
            by_native[native_key] = identity
        by_key[(identity.provider, identity.identifier)] = identity
    return list(by_key.values())


def _reconcile_accesses(existing: Iterable[Access], imported: Iterable[Access]) -> list[Access]:
    existing_by_name = {(access.provider, access.name): access for access in existing}
    existing_by_native = {
        (access.provider, access.control_object.native_id, access.permission.identifier): access
        for access in existing
        if access.control_object.native_id
    }
    reconciled: list[Access] = []
    seen: set[tuple[str, str]] = set()
    for access in imported:
        previous = None
        if access.control_object.native_id:
            previous = existing_by_native.get(
                (access.provider, access.control_object.native_id, access.permission.identifier)
            )
        else:
            previous = existing_by_name.get((access.provider, access.name))
        if previous is not None:
            access.id = previous.id
        key = (access.provider, access.name)
        if key not in seen:
            reconciled.append(access)
            seen.add(key)
    return reconciled


def _reconcile_assignments(
    existing: Iterable[AccessAssignment], imported: Iterable[AccessAssignment]
) -> list[AccessAssignment]:
    existing_by_key = {
        assignment.comparison_key() + (assignment.origin_fingerprint,): assignment
        for assignment in existing
    }
    reconciled: list[AccessAssignment] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for assignment in imported:
        key = assignment.comparison_key() + (assignment.origin_fingerprint,)
        previous = existing_by_key.get(key)
        if previous is not None:
            assignment.id = previous.id
        if key not in seen:
            reconciled.append(assignment)
            seen.add(key)
    return reconciled


def _resolve_unresolved_assignments(repo: Repository) -> None:
    identities = _load_identities(repo)
    identities_by_sid = _unique_identities_by_native_id(identities)
    identities_by_ldap_dn = _unique_identities_by_ldap_dn(identities)
    identities_by_provider_uid = _unique_identities_by_provider_uid(identities)
    for assignment in _unresolved_assignments_for_resolution(repo):
        if not assignment.origin.raw.get("unresolved"):
            continue
        identity = None
        sid = assignment.origin.raw.get("member_sid")
        if sid:
            identity = identities_by_sid.get(str(sid))
        member_uuid = assignment.origin.raw.get("member_entry_uuid") or assignment.origin.raw.get(
            "entryUUID"
        )
        if identity is None and member_uuid:
            identity = identities_by_sid.get(str(member_uuid))
        member_dn = assignment.origin.raw.get("member_dn")
        if identity is None and member_dn:
            identity = identities_by_ldap_dn.get(_canonical_dn(str(member_dn)))
        member_uid = assignment.origin.raw.get("member_uid") or assignment.origin.raw.get(
            "memberUid"
        )
        if identity is None and member_uid:
            identity = identities_by_provider_uid.get((assignment.provider, str(member_uid)))
        if identity is None:
            continue
        assignment.identity_provider = identity.provider
        assignment.identity_identifier = identity.identifier
        assignment.origin.raw["cross_domain_resolved"] = identity.provider != assignment.provider
        assignment.origin.raw.pop("unresolved", None)
        assignment.origin.raw.pop("unresolved_foreign_principal", None)
        assignment.origin.raw.pop("ambiguous", None)
        repo.upsert("access_assignments", assignment)


def _retain_non_authoritative_unresolved(result: ImportResult) -> None:
    unresolved = [asdict(item) for item in result.assignments if item.origin.raw.get("unresolved")]
    if unresolved:
        result.batch.scope["non_authoritative_unresolved_assignments"] = unresolved


def _unresolved_assignments_for_resolution(repo: Repository) -> list[AccessAssignment]:
    assignments = [item for item in _load_assignments(repo) if item.origin.raw.get("unresolved")]
    for row in repo.list_payloads("imports"):
        scope = row.get("scope", {})
        if not isinstance(scope, dict):
            continue
        for payload in scope.get("non_authoritative_unresolved_assignments", []):
            if isinstance(payload, dict):
                assignments.append(hydrate_assignment(payload))
    return assignments


def _unique_identities_by_native_id(identities: Iterable[Identity]) -> dict[str, Identity]:
    found: dict[str, Identity | None] = {}
    for identity in identities:
        if not identity.native_id:
            continue
        if identity.native_id in found:
            found[identity.native_id] = None
        else:
            found[identity.native_id] = identity
    return {native_id: identity for native_id, identity in found.items() if identity is not None}


def _unique_identities_by_ldap_dn(identities: Iterable[Identity]) -> dict[str, Identity]:
    found: dict[str, Identity | None] = {}
    for identity in identities:
        dn = identity.metadata.get("dn")
        if not dn:
            continue
        canonical = _canonical_dn(str(dn))
        if canonical in found:
            found[canonical] = None
        else:
            found[canonical] = identity
    return {dn: identity for dn, identity in found.items() if identity is not None}


def _unique_identities_by_provider_uid(
    identities: Iterable[Identity],
) -> dict[tuple[str, str], Identity]:
    found: dict[tuple[str, str], Identity | None] = {}
    for identity in identities:
        uid = identity.metadata.get("uid")
        if not uid:
            continue
        key = (identity.provider, str(uid))
        if key in found:
            found[key] = None
        else:
            found[key] = identity
    return {key: identity for key, identity in found.items() if identity is not None}


def load_classification_rules(path: str | Path | None) -> dict[str, object] | None:
    if path is None:
        return None
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("classification rules must be a JSON object")
    return data


def _zip_source_type(path: Path) -> str | None:
    if path.stat().st_size > 500_000_000:
        raise ValueError("Import archive exceeds configured maximum size")
    try:
        with ZipFile(path) as zf:
            names = zf.namelist()
            if len(names) != len(set(names)):
                raise ValueError("Archive contains duplicate filenames")
            if len(names) > 16:
                raise ValueError("Archive contains too many files")
            if any(name.startswith("/") or ".." in Path(name).parts for name in names):
                raise ValueError("Unsafe ZIP path detected")
            if "manifest.yaml" not in names:
                raise ValueError("Archive is missing required files: ['manifest.yaml']")
            total = 0
            for info in zf.infolist():
                if info.file_size > 1_000_000_000:
                    raise ValueError("Archive member exceeds configured maximum size")
                total += info.file_size
                if total > 1_500_000_000:
                    raise ValueError("Archive uncompressed size exceeds configured maximum size")
            manifest = _read_manifest(zf.read("manifest.yaml").decode("utf-8-sig"))
    except BadZipFile as exc:
        raise ValueError("Invalid ZIP archive") from exc
    value = manifest.get("source_type")
    if value is not None:
        return str(value)
    return None


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
