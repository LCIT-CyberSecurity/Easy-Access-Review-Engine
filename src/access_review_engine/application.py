from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from access_review_engine.domain import (
    Access,
    AccessAssignment,
    Completeness,
    GoldenSourceVersion,
    Identity,
    Provider,
)
from access_review_engine.importers.ad import ImportResult, import_ad_zip
from access_review_engine.importers.openldap import import_openldap_ldif
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
    result = (
        import_ad_zip(file_path, known_identities=known_identities, classification_rules=classification_rules)
        if file_path.suffix.lower() == ".zip"
        else import_openldap_ldif(file_path, provider_name)
    )
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

    repo.upsert("providers", result.provider)
    repo.insert_append_only("imports", result.batch)

    existing_identities = _load_identities(repo, result.provider.name)
    imported_identities = _dedupe_identities(result.identities)
    merged_identities = reconcile_identities(
        existing_identities,
        imported_identities,
        completeness=result.batch.completeness,
        scope=result.batch.scope,
    )
    for identity in merged_identities:
        repo.upsert("identities", identity)

    accesses = _reconcile_accesses(_load_accesses(repo, result.provider.name), result.accesses)
    for access in accesses:
        repo.upsert("accesses", access)

    authoritative = _is_authoritative_full(result)
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
    return (
        result.batch.completeness == Completeness.FULL
        and scope.get("completeness") in {None, Completeness.FULL, "full"}
        and scope.get("type", "all") == "all"
        and not scope.get("collection_errors")
    )


def _load_identities(repo: Repository, provider: str | None = None) -> list[Identity]:
    rows = repo.list_payloads_by_provider("identities", provider) if provider else repo.list_payloads("identities")
    return [hydrate_identity(row) for row in rows]


def _load_accesses(repo: Repository, provider: str | None = None) -> list[Access]:
    rows = repo.list_payloads_by_provider("accesses", provider) if provider else repo.list_payloads("accesses")
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
        previous = previous or existing_by_name.get((access.provider, access.name))
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
    identities_by_sid = _unique_identities_by_sid(_load_identities(repo))
    for assignment in _load_assignments(repo):
        sid = assignment.origin.raw.get("member_sid")
        if not sid or not assignment.origin.raw.get("unresolved"):
            continue
        identity = identities_by_sid.get(str(sid))
        if identity is None:
            continue
        assignment.identity_provider = identity.provider
        assignment.identity_identifier = identity.identifier
        assignment.origin.raw["cross_domain_resolved"] = identity.provider != assignment.provider
        assignment.origin.raw.pop("unresolved", None)
        assignment.origin.raw.pop("unresolved_foreign_principal", None)
        repo.upsert("access_assignments", assignment)


def _unique_identities_by_sid(identities: Iterable[Identity]) -> dict[str, Identity]:
    found: dict[str, Identity | None] = {}
    for identity in identities:
        if not identity.native_id:
            continue
        if identity.native_id in found:
            found[identity.native_id] = None
        else:
            found[identity.native_id] = identity
    return {sid: identity for sid, identity in found.items() if identity is not None}


def load_classification_rules(path: str | Path | None) -> dict[str, object] | None:
    if path is None:
        return None
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("classification rules must be a JSON object")
    return data
