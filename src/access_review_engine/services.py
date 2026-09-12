from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Iterable

from access_review_engine.domain import (
    Access,
    AccessAssignment,
    AccessPath,
    AccessRelation,
    AccessRelationType,
    AuthenticationPosture,
    AuditEvent,
    Campaign,
    CampaignStatus,
    ComparisonState,
    Completeness,
    Decision,
    DecisionValue,
    EffectiveAccess,
    EffectiveAccessEvaluation,
    Finding,
    GoldenSource,
    GoldenSourceAssignment,
    GoldenSourceVersion,
    Identity,
    IdentityStatus,
    IdentityType,
    JsonDict,
    ObjectRef,
    OwnerRef,
    RemediationAction,
    RemediationActionType,
    ReviewItem,
    Snapshot,
    stable_checksum,
)


def identity_key(identity: Identity) -> tuple[str, str]:
    return (identity.provider, identity.identifier)


def access_key(access: Access) -> tuple[str, str]:
    return (access.provider, access.name)


def relation_key(relation: AccessRelation) -> tuple[str, str, str, str, str, str]:
    return relation.key()


def calculate_effective_accesses(
    assignments: Iterable[AccessAssignment],
    relations: Iterable[AccessRelation] = (),
    accesses: Iterable[Access] | None = None,
    max_paths_per_access: int = 100,
) -> EffectiveAccessEvaluation:
    """Resolve direct and derived accesses from AccessAssignment plus AccessRelation grants.

    Only direct observations remain AccessAssignment objects. Derived accesses are calculated from
    the relation graph and keep every provenance path that reaches the same effective access.
    Cycles are reported and traversal of that cyclic path stops.
    """
    if max_paths_per_access < 1:
        raise ValueError("max_paths_per_access must be at least 1")
    access_keys = {access_key(access) for access in accesses} if accesses is not None else None
    diagnostics: list[JsonDict] = []
    adjacency: dict[tuple[str, str], list[AccessRelation]] = {}
    seen_relations: set[tuple[str, str, str, str, str, str]] = set()

    for relation in sorted(relations, key=lambda item: item.key()):
        if relation.relation_type != AccessRelationType.GRANTS:
            diagnostics.append(_relation_diagnostic("unsupported_relation_type", relation))
            continue
        if relation.key() in seen_relations:
            continue
        seen_relations.add(relation.key())
        missing: list[str] = []
        if access_keys is not None and relation.parent_key() not in access_keys:
            missing.append("parent_access")
        if access_keys is not None and relation.child_key() not in access_keys:
            missing.append("child_access")
        if missing:
            diagnostic = _relation_diagnostic("unresolved_access_relation", relation)
            diagnostic["missing"] = missing
            diagnostics.append(diagnostic)
            continue
        adjacency.setdefault(relation.parent_key(), []).append(relation)

    results: dict[tuple[str, str, str, str], EffectiveAccess] = {}
    for assignment in sorted(
        assignments,
        key=lambda item: (
            item.identity_provider,
            item.identity_identifier,
            item.provider,
            item.access_name,
            item.origin_fingerprint,
            item.id,
        ),
    ):
        root_key = (assignment.provider, assignment.access_name)
        if access_keys is not None and root_key not in access_keys:
            diagnostics.append(
                {
                    "type": "unresolved_direct_assignment",
                    "assignment_id": assignment.id,
                    "access_provider": assignment.provider,
                    "access_name": assignment.access_name,
                    "identity_provider": assignment.identity_provider,
                    "identity_identifier": assignment.identity_identifier,
                }
            )
            continue
        root_ref = ObjectRef(*root_key)
        root_path = AccessPath(
            identity_provider=assignment.identity_provider,
            identity_identifier=assignment.identity_identifier,
            access_chain=(root_ref,),
            assignment_id=assignment.id,
        )
        _add_effective_access(results, assignment, root_key, True, root_path)

        stack: list[tuple[tuple[str, str], tuple[ObjectRef, ...], tuple[str, ...]]] = [
            (root_key, (root_ref,), ())
        ]
        while stack:
            current_key, chain, relation_ids = stack.pop()
            for relation in reversed(adjacency.get(current_key, [])):
                child_key = relation.child_key()
                child_ref = ObjectRef(*child_key)
                if child_ref in chain:
                    diagnostics.append(
                        {
                            "type": "cycle_detected",
                            "relation_id": relation.id,
                            "identity_provider": assignment.identity_provider,
                            "identity_identifier": assignment.identity_identifier,
                            "access_chain": [ref.key() for ref in (*chain, child_ref)],
                        }
                    )
                    continue
                child_chain = (*chain, child_ref)
                child_relation_ids = (*relation_ids, relation.id)
                result_key = (
                    assignment.identity_provider,
                    assignment.identity_identifier,
                    child_key[0],
                    child_key[1],
                )
                existing = results.get(result_key)
                if existing is not None and len(existing.paths) >= max_paths_per_access:
                    diagnostics.append(
                        {
                            "type": "path_limit_reached",
                            "identity_provider": assignment.identity_provider,
                            "identity_identifier": assignment.identity_identifier,
                            "access_provider": child_key[0],
                            "access_name": child_key[1],
                            "max_paths_per_access": max_paths_per_access,
                        }
                    )
                    continue
                path = AccessPath(
                    identity_provider=assignment.identity_provider,
                    identity_identifier=assignment.identity_identifier,
                    access_chain=child_chain,
                    assignment_id=assignment.id,
                    relation_ids=child_relation_ids,
                )
                _add_effective_access(results, assignment, child_key, False, path)
                stack.append((child_key, child_chain, child_relation_ids))

    return EffectiveAccessEvaluation(
        effective_accesses=[results[key] for key in sorted(results)],
        diagnostics=sorted(diagnostics, key=lambda item: str(item)),
    )


def effective_access_diff(
    old: EffectiveAccessEvaluation, new: EffectiveAccessEvaluation
) -> list[dict[str, str]]:
    old_keys = {item.key(): item for item in old.effective_accesses}
    new_keys = {item.key(): item for item in new.effective_accesses}
    rows: list[dict[str, str]] = []
    for key in sorted(old_keys.keys() | new_keys.keys()):
        if key in old_keys and key in new_keys:
            status = "unchanged"
        elif key in old_keys:
            status = "removed"
        else:
            status = "added"
        rows.append(
            {
                "status": status,
                "identity_provider": key[0],
                "identity_identifier": key[1],
                "access_provider": key[2],
                "access_name": key[3],
            }
        )
    return rows


def _add_effective_access(
    results: dict[tuple[str, str, str, str], EffectiveAccess],
    assignment: AccessAssignment,
    access_ref: tuple[str, str],
    direct: bool,
    path: AccessPath,
) -> None:
    key = (
        assignment.identity_provider,
        assignment.identity_identifier,
        access_ref[0],
        access_ref[1],
    )
    result = results.get(key)
    if result is None:
        result = EffectiveAccess(
            identity_provider=assignment.identity_provider,
            identity_identifier=assignment.identity_identifier,
            access_provider=access_ref[0],
            access_name=access_ref[1],
            direct=direct,
        )
        results[key] = result
    result.direct = result.direct or direct
    if path not in result.paths:
        result.paths.append(path)


def _relation_diagnostic(kind: str, relation: AccessRelation) -> JsonDict:
    return {
        "type": kind,
        "relation_id": relation.id,
        "parent_provider": relation.parent_provider,
        "parent_access_name": relation.parent_access_name,
        "child_provider": relation.child_provider,
        "child_access_name": relation.child_access_name,
        "relation_type": relation.relation_type,
    }


def validate_owner(owner: OwnerRef | None, subject: Identity, identities: dict[tuple[str, str], Identity]) -> bool:
    if owner is None:
        return False
    if (owner.provider, owner.identity) == identity_key(subject):
        return False
    owner_identity = identities.get((owner.provider, owner.identity))
    return (
        owner_identity is not None
        and owner_identity.type == IdentityType.USER_ACCOUNT
        and owner_identity.status == IdentityStatus.ACTIVE
    )


def owner_findings(identity: Identity, identities: dict[tuple[str, str], Identity]) -> list[str]:
    findings: list[str] = []
    if _truthy_metadata(identity.metadata.get("locked_out")):
        findings.append(Finding.ACCOUNT_LOCKED)
    if _truthy_metadata(identity.metadata.get("account_expired")) or _is_past_datetime(
        identity.metadata.get("account_expiration_date")
    ):
        findings.append(Finding.ACCOUNT_EXPIRED)
    if identity.account_owner and not validate_owner(identity.account_owner, identity, identities):
        findings.append(Finding.INVALID_OWNER)
    if identity.type == IdentityType.TECHNICAL_ACCOUNT and not identity.built_in and not identity.account_owner:
        findings.append(Finding.TECHNICAL_ACCOUNT_WITHOUT_OWNER)
    if identity.type == IdentityType.SHARED_ACCOUNT and not identity.account_owner:
        findings.append(Finding.SHARED_ACCOUNT_WITHOUT_OWNER)
    return findings


def _truthy_metadata(value: object) -> bool:
    return value is True or str(value).lower() in {"1", "true", "yes", "y"}


def _is_past_datetime(value: object) -> bool:
    if not value:
        return False
    text = str(value).strip()
    for fmt in (None, "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%m/%d/%Y %I:%M:%S %p"):
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00")) if fmt is None else datetime.strptime(text, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt < datetime.now(UTC)
        except ValueError:
            continue
    return False


def reconcile_identities(
    existing: Iterable[Identity],
    imported: Iterable[Identity],
    completeness: str = "full",
    scope: dict[str, object] | None = None,
    authoritative: bool | None = None,
) -> list[Identity]:
    """Merge imported identities while preserving internal ids across provider/native_id renames."""
    existing_list = list(existing)
    imported_list = list(imported)
    existing_by_native = {
        (identity.provider, identity.native_id): identity
        for identity in existing_list
        if identity.native_id is not None
    }
    existing_by_ref = {identity_key(identity): identity for identity in existing_list}
    imported_refs: set[tuple[str, str]] = set()
    preserved_existing_ids: set[str] = set()
    merged: list[Identity] = []
    for identity in imported_list:
        previous = (
            existing_by_native.get((identity.provider, identity.native_id))
            if identity.native_id is not None
            else existing_by_ref.get(identity_key(identity))
        )
        if previous is not None:
            identity.id = previous.id
            preserved_existing_ids.add(previous.id)
        imported_refs.add(identity_key(identity))
        merged.append(identity)

    if authoritative is None:
        authoritative = completeness == "full"

    if authoritative:
        for identity in existing_list:
            if (
                identity.id not in preserved_existing_ids
                and (identity.native_id is not None or identity_key(identity) not in imported_refs)
                and _identity_in_scope(identity, scope)
            ):
                deleted = Identity(**(asdict(identity) | {"status": IdentityStatus.DELETED}))
                merged.append(deleted)
    return merged


def _identity_in_scope(identity: Identity, scope: dict[str, object] | None) -> bool:
    if not scope:
        return True
    if scope.get("type") == "all":
        return True
    if scope.get("type") == "providers":
        return identity.provider in set(scope.get("values", []))
    if scope.get("type") == "identity_types":
        return identity.type in set(scope.get("values", []))
    return False


def compare_snapshot(
    snapshot: Snapshot,
    golden_version: GoldenSourceVersion | None,
    import_scope: dict[str, object] | None = None,
) -> list[dict[str, object]]:
    identities = {identity_key(identity): identity for identity in snapshot.identities}
    accesses = {access_key(access): access for access in snapshot.accesses}
    observed_assignments = {assignment.comparison_key(): assignment for assignment in snapshot.access_assignments}
    observed_legacy = set(observed_assignments)
    observed_legacy_aliases: set[tuple[str, str, str, str]] = set()
    observed_legacy_without_stable: set[tuple[str, str, str, str]] = set()
    observed_stable: dict[tuple[str, str, str, str], tuple[str, str, str, str] | None] = {}
    assignment_origins: dict[tuple[str, str, str, str], list[AccessAssignment]] = {}
    for assignment in snapshot.access_assignments:
        legacy_key = assignment.comparison_key()
        assignment_origins.setdefault(legacy_key, []).append(assignment)
        access = accesses.get((assignment.provider, assignment.access_name))
        legacy_alias = (
            (
                assignment.provider,
                access.display_name,
                assignment.identity_provider,
                assignment.identity_identifier,
            )
            if (
                access is not None
                and access.display_name
                and access.display_name != assignment.access_name
            )
            else None
        )
        stable_key = _observed_stable_key(assignment, accesses, identities)
        if stable_key is None:
            observed_legacy_without_stable.add(legacy_key)
            if legacy_alias is not None:
                observed_legacy_aliases.add(legacy_alias)
                observed_legacy_without_stable.add(legacy_alias)
            continue
        if legacy_alias is not None:
            observed_legacy_aliases.add(legacy_alias)
        observed_stable[stable_key] = legacy_key if stable_key not in observed_stable else None

    expected_items = list(golden_version.assignments) if golden_version else []
    expected_stable = {
        stable_key: assignment
        for assignment in expected_items
        if (stable_key := assignment.stable_key()) is not None
    }

    rows: list[dict[str, object]] = []
    matched_observed: set[tuple[str, str, str, str]] = set()

    for expected in sorted(expected_items, key=lambda item: item.key()):
        expected_key = expected.key()
        stable_key = expected.stable_key()
        observed_key: tuple[str, str, str, str] | None = None
        if stable_key is not None:
            candidate = observed_stable.get(stable_key)
            if candidate is not None:
                observed_key = candidate
            elif expected_key in observed_legacy_without_stable:
                observed_key = expected_key
        elif expected_key in observed_legacy_without_stable:
            observed_key = expected_key

        row_key = observed_key or expected_key
        if observed_key is not None:
            matched_observed.add(observed_key)
            classification = (
                ComparisonState.UNKNOWN_DUE_TO_SCOPE
                if _is_incomplete_scope(import_scope)
                else ComparisonState.EXPECTED_AND_OBSERVED
            )
        elif stable_key is None and expected_key in (observed_legacy | observed_legacy_aliases):
            classification = ComparisonState.UNKNOWN_DUE_TO_SCOPE
        elif _in_authoritative_scope(expected.access_provider, expected.access_name, import_scope):
            classification = ComparisonState.MISSING
        else:
            classification = ComparisonState.UNKNOWN_DUE_TO_SCOPE
        rows.append(_comparison_row(
            row_key,
            expected=True,
            observed=observed_key is not None,
            classification=classification,
            identities=identities,
            accesses=accesses,
            assignment_origins=assignment_origins,
            import_scope=import_scope,
        ))

    for observed_key in sorted(observed_legacy):
        if observed_key in matched_observed:
            continue
        assignment = observed_assignments[observed_key]
        stable_key = _observed_stable_key(assignment, accesses, identities)
        if stable_key is not None and stable_key in expected_stable:
            continue
        if golden_version is None:
            classification = ComparisonState.NO_REFERENCE
            expected = False
        else:
            classification = ComparisonState.UNEXPECTED
            expected = False
        rows.append(_comparison_row(
            observed_key,
            expected=expected,
            observed=True,
            classification=classification,
            identities=identities,
            accesses=accesses,
            assignment_origins=assignment_origins,
            import_scope=import_scope,
        ))

    return sorted(
        rows,
        key=lambda row: (
            str(row["access_provider"]),
            str(row["access_name"]),
            str(row["identity_provider"]),
            str(row["identity_identifier"]),
            str(row["classification"]),
        ),
    )


def _comparison_row(
    key: tuple[str, str, str, str],
    expected: bool,
    observed: bool,
    classification: str,
    identities: dict[tuple[str, str], Identity],
    accesses: dict[tuple[str, str], Access],
    assignment_origins: dict[tuple[str, str, str, str], list[AccessAssignment]],
    import_scope: dict[str, object] | None,
) -> dict[str, object]:
    access_provider, access_name, identity_provider, identity_identifier = key
    identity = identities.get((identity_provider, identity_identifier))
    findings: list[str] = []
    for assignment in assignment_origins.get(key, []):
        if assignment.origin.raw.get("unresolved_foreign_principal") or assignment.origin.raw.get("unresolved"):
            findings.append(Finding.UNRESOLVED_FOREIGN_PRINCIPAL)
        if assignment.origin.raw.get("unknown_member_type"):
            findings.append(Finding.UNKNOWN_MEMBER_TYPE)
    if _is_incomplete_scope(import_scope):
        findings.append(Finding.COLLECTION_INCOMPLETE)
    if identity is None:
        findings.append(Finding.UNKNOWN_IDENTITY)
    else:
        if observed and identity.status == IdentityStatus.DISABLED:
            findings.append(Finding.DISABLED_WITH_ACCESS)
        if observed and identity.status == IdentityStatus.DELETED:
            findings.append(Finding.DELETED_WITH_ACCESS)
        findings.extend(owner_findings(identity, identities))

    access = accesses.get((access_provider, access_name))
    return {
        "access_provider": access_provider,
        "access_name": access_name,
        "identity_provider": identity_provider,
        "identity_identifier": identity_identifier,
        "expected": expected,
        "observed": observed,
        "classification": str(classification),
        "findings": sorted({str(item) for item in findings}),
        "access": asdict(access) if access else None,
        "identity": asdict(identity) if identity else None,
    }


def _observed_stable_key(
    assignment: AccessAssignment,
    accesses: dict[tuple[str, str], Access],
    identities: dict[tuple[str, str], Identity],
) -> tuple[str, str, str, str] | None:
    access = accesses.get((assignment.provider, assignment.access_name))
    identity = identities.get((assignment.identity_provider, assignment.identity_identifier))
    if identity is None:
        return None
    raw_access_native = assignment.origin.raw.get("GroupSID") or assignment.origin.raw.get("group_native_id")
    access_native_id = str(raw_access_native) if raw_access_native else None
    if access_native_id is None and access and access.control_object:
        access_native_id = access.control_object.native_id
    permission_id = access.permission.identifier if access and access.permission else "member"
    if not access_native_id and not identity.native_id:
        return None
    access_ref = (
        f"native:{access_native_id}:{permission_id}"
        if access_native_id
        else f"name:{assignment.access_name}"
    )
    identity_ref = (
        f"native:{identity.native_id}"
        if identity.native_id
        else f"identifier:{assignment.identity_identifier}"
    )
    return (assignment.provider, access_ref, assignment.identity_provider, identity_ref)


def _is_incomplete_scope(scope: dict[str, object] | None) -> bool:
    return bool(scope and scope.get("completeness") not in {None, "full", Completeness.FULL})


def _in_authoritative_scope(provider: str, access_name: str, scope: dict[str, object] | None) -> bool:
    if _is_incomplete_scope(scope):
        return False
    if not scope:
        return True
    if scope.get("type") == "all":
        return True
    if scope.get("type") == "providers":
        return provider in set(scope.get("values", []))
    if scope.get("type") == "accesses":
        return access_name in set(scope.get("values", []))
    return False


def create_snapshot(
    providers: list[object],
    identities: list[Identity],
    resources: list[object],
    accesses: list[Access],
    assignments: list[AccessAssignment],
    source_import_ids: list[str],
    golden_version: GoldenSourceVersion | None = None,
    import_scope: dict[str, object] | None = None,
    access_relations: list[AccessRelation] | None = None,
    authentication_posture: AuthenticationPosture | None = None,
) -> Snapshot:
    snapshot = Snapshot(
        providers=deepcopy(providers),  # type: ignore[arg-type]
        identities=deepcopy(identities),
        resources=deepcopy(resources),  # type: ignore[arg-type]
        accesses=deepcopy(accesses),
        access_assignments=deepcopy(assignments),
        source_import_ids=list(source_import_ids),
        access_relations=deepcopy(list(access_relations or [])),
        authentication_posture=deepcopy(authentication_posture),
    )
    snapshot.comparison_states = compare_snapshot(snapshot, golden_version, import_scope)
    return snapshot.finalize()


def create_golden_source(name: str, display_name: str | None = None) -> GoldenSource:
    return GoldenSource(name=name, display_name=display_name or name)


def create_golden_version(
    golden_source: GoldenSource,
    assignments: Iterable[GoldenSourceAssignment],
    source_type: str,
    previous_versions: Iterable[GoldenSourceVersion] = (),
    source_snapshot_id: str | None = None,
    source_campaign_id: str | None = None,
    parent_version_id: str | None = None,
    comment: str | None = None,
    golden_authentication_policy: AuthenticationPosture | None = None,
) -> GoldenSourceVersion:
    previous = list(previous_versions)
    version = max((item.version for item in previous), default=0) + 1
    incoming = list(assignments)
    _reject_duplicate_stable_golden_keys(incoming)
    ordered = sorted(set(incoming), key=lambda item: item.key())
    checksum = stable_checksum({
        "assignments": [asdict(item) for item in ordered],
        "golden_authentication_policy": asdict(golden_authentication_policy) if golden_authentication_policy else None,
    })
    return GoldenSourceVersion(
        golden_source_id=golden_source.id,
        version=version,
        source_type=source_type,
        checksum=checksum,
        assignments=list(ordered),
        source_snapshot_id=source_snapshot_id,
        source_campaign_id=source_campaign_id,
        parent_version_id=parent_version_id,
        comment=comment,
        golden_authentication_policy=deepcopy(golden_authentication_policy),
    )


def promote_snapshot(
    golden_source: GoldenSource,
    snapshot: Snapshot,
    previous_versions: Iterable[GoldenSourceVersion] = (),
) -> GoldenSourceVersion:
    identities = {identity_key(identity): identity for identity in snapshot.identities}
    accesses = {access_key(access): access for access in snapshot.accesses}
    if any(
        Finding.COLLECTION_INCOMPLETE in set(row.get("findings", []))
        for row in snapshot.comparison_states
    ):
        raise ValueError("Cannot promote a scoped or incomplete snapshot to Golden Source")
    previous = list(previous_versions)
    if previous:
        latest = max(previous, key=lambda item: item.version)
        snapshot_providers = {provider.name for provider in snapshot.providers}
        golden_providers = {assignment.access_provider for assignment in latest.assignments}
        if snapshot_providers and golden_providers - snapshot_providers:
            raise ValueError(
                "Cannot promote provider-scoped snapshot over a Golden Source "
                "containing other providers"
            )
    assignments = []
    for item in snapshot.access_assignments:
        access = accesses.get((item.provider, item.access_name))
        identity = identities.get((item.identity_provider, item.identity_identifier))
        assignments.append(
            GoldenSourceAssignment(
                access_provider=item.provider,
                access_name=item.access_name,
                identity_provider=item.identity_provider,
                identity_identifier=item.identity_identifier,
                access_native_id=access.control_object.native_id if access and access.control_object else None,
                access_permission=access.permission.identifier if access and access.permission else None,
                identity_native_id=identity.native_id if identity else None,
            )
        )
    parent_id = max(previous, key=lambda item: item.version).id if previous else None
    return create_golden_version(
        golden_source,
        assignments,
        "promoted_observed_snapshot",
        previous,
        source_snapshot_id=snapshot.id,
        parent_version_id=parent_id,
        golden_authentication_policy=snapshot.authentication_posture,
    )


def _reject_duplicate_stable_golden_keys(assignments: Iterable[GoldenSourceAssignment]) -> None:
    seen: set[tuple[str, str, str, str]] = set()
    for item in assignments:
        stable_key = item.stable_key()
        if stable_key is None:
            continue
        if stable_key in seen:
            raise ValueError("Golden Source contains duplicate stable assignment key")
        seen.add(stable_key)


def golden_diff(
    old: GoldenSourceVersion, new: GoldenSourceVersion
) -> list[dict[str, str]]:
    old_remaining = set(old.assignments)
    new_remaining = set(new.assignments)
    rows: list[dict[str, str]] = []

    for _, old_item, new_item in _matching_golden_stable_items(old_remaining, new_remaining):
        old_remaining.discard(old_item)
        new_remaining.discard(new_item)
        rows.append(_golden_diff_row("unchanged", new_item))

    for _, old_item, new_item in _matching_golden_legacy_items(old_remaining, new_remaining):
        old_remaining.discard(old_item)
        new_remaining.discard(new_item)
        rows.append(_golden_diff_row("unchanged", new_item))

    rows.extend(_golden_diff_row("removed", item) for item in old_remaining)
    rows.extend(_golden_diff_row("added", item) for item in new_remaining)
    return sorted(
        rows,
        key=lambda row: (
            row["access_provider"],
            row["access_name"],
            row["identity_provider"],
            row["identity_identifier"],
            row["status"],
        ),
    )


def _matching_golden_stable_items(
    old_items: set[GoldenSourceAssignment], new_items: set[GoldenSourceAssignment]
) -> list[tuple[tuple[str, str, str, str], GoldenSourceAssignment, GoldenSourceAssignment]]:
    old_by_key = _unique_golden_by_key(
        (item for item in old_items if item.stable_key()), stable=True
    )
    new_by_key = _unique_golden_by_key(
        (item for item in new_items if item.stable_key()), stable=True
    )
    return [
        (key, old_by_key[key], new_by_key[key])
        for key in sorted(old_by_key.keys() & new_by_key.keys())
    ]


def _matching_golden_legacy_items(
    old_items: set[GoldenSourceAssignment], new_items: set[GoldenSourceAssignment]
) -> list[tuple[tuple[str, str, str, str], GoldenSourceAssignment, GoldenSourceAssignment]]:
    old_by_key = _unique_golden_by_key(old_items, stable=False)
    new_by_key = _unique_golden_by_key(new_items, stable=False)
    matches = []
    for key in sorted(old_by_key.keys() & new_by_key.keys()):
        old_item = old_by_key[key]
        new_item = new_by_key[key]
        if old_item.stable_key() is not None and new_item.stable_key() is not None:
            continue
        matches.append((key, old_item, new_item))
    return matches


def _unique_golden_by_key(
    assignments: Iterable[GoldenSourceAssignment], stable: bool
) -> dict[tuple[str, str, str, str], GoldenSourceAssignment]:
    result: dict[tuple[str, str, str, str], GoldenSourceAssignment] = {}
    ambiguous: set[tuple[str, str, str, str]] = set()
    for item in assignments:
        key = item.stable_key() if stable else item.key()
        if key is None:
            continue
        if key in result:
            ambiguous.add(key)
        result[key] = item
    for key in ambiguous:
        result.pop(key, None)
    return result


def _golden_diff_row(status: str, item: GoldenSourceAssignment) -> dict[str, str]:
    return {
        "status": status,
        "access_provider": item.access_provider,
        "access_name": item.access_name,
        "identity_provider": item.identity_provider,
        "identity_identifier": item.identity_identifier,
    }


def open_campaign(
    campaign: Campaign,
    snapshot: Snapshot,
    fallback_reviewer: OwnerRef | None = None,
) -> tuple[Campaign, list[ReviewItem]]:
    if campaign.status != CampaignStatus.DRAFT:
        raise ValueError("Only draft campaigns can be opened")
    identities = {identity_key(identity): identity for identity in snapshot.identities}
    accesses = {access_key(access): access for access in snapshot.accesses}
    items: list[ReviewItem] = []
    for row in snapshot.comparison_states:
        access = accesses.get((str(row["access_provider"]), str(row["access_name"])))
        identity = identities.get((str(row["identity_provider"]), str(row["identity_identifier"])))
        reviewer = _resolve_reviewer(access, identity, campaign, fallback_reviewer)
        if reviewer is None and not campaign.allow_unresolved_reviewers:
            raise ValueError("Campaign has review items without resolvable reviewer")
        items.append(
            ReviewItem(
                campaign_id=campaign.id,
                identity_provider=str(row["identity_provider"]),
                identity_identifier=str(row["identity_identifier"]),
                identity_status=identity.status if identity else IdentityStatus.UNKNOWN,
                access_provider=str(row["access_provider"]),
                access_name=str(row["access_name"]),
                control_object=asdict(access.control_object) if access and access.control_object else {},
                permission=asdict(access.permission) if access and access.permission else {},
                target=asdict(access.target) if access and access.target else None,
                description=access.description if access else None,
                origin=None,
                expected=bool(row["expected"]),
                observed=bool(row["observed"]),
                classification=str(row["classification"]),
                findings=list(row["findings"]),  # type: ignore[arg-type]
                account_owner=identity.account_owner if identity else None,
                access_owner=access.access_owner if access else None,
                reviewer=reviewer,
            )
        )
    campaign.status = CampaignStatus.OPEN
    from access_review_engine.domain import now_utc

    campaign.opened_at = now_utc()
    return campaign, items


def _resolve_reviewer(
    access: Access | None,
    identity: Identity | None,
    campaign: Campaign,
    fallback_reviewer: OwnerRef | None,
) -> OwnerRef | None:
    return (
        access.access_owner
        if access and access.access_owner
        else identity.account_owner
        if identity and identity.account_owner
        else campaign.default_reviewer
        or campaign.manager
        or fallback_reviewer
    )


def create_decision(review_item: ReviewItem, value: str, comment: str | None, decided_by: str | None) -> Decision:
    if value not in set(DecisionValue):
        raise ValueError(f"Unsupported decision: {value}")
    if value in {DecisionValue.REVOKE, DecisionValue.NOT_APPLICABLE} and not comment:
        raise ValueError(f"{value} decisions require a comment")
    return Decision(review_item_id=review_item.id, value=value, comment=comment, decided_by=decided_by)


def latest_decisions(decisions: Iterable[Decision]) -> dict[str, Decision]:
    latest: dict[str, Decision] = {}
    for decision in sorted(decisions, key=lambda item: item.created_at):
        latest[decision.review_item_id] = decision
    return latest


def close_campaign(campaign: Campaign, review_items: list[ReviewItem], decisions: list[Decision]) -> Campaign:
    decided = set(latest_decisions(decisions))
    pending = [item.id for item in review_items if item.id not in decided]
    if pending:
        raise ValueError("Cannot close campaign with pending review items")
    campaign.status = CampaignStatus.CLOSED
    from access_review_engine.domain import now_utc

    campaign.closed_at = now_utc()
    return campaign


def promote_campaign(
    golden_source: GoldenSource,
    campaign: Campaign,
    review_items: list[ReviewItem],
    decisions: list[Decision],
    previous_version: GoldenSourceVersion | None,
    mode: str = "replace_scope",
) -> GoldenSourceVersion:
    latest = latest_decisions(decisions)
    if any(item.id not in latest for item in review_items):
        raise ValueError("Cannot promote campaign with pending decisions")
    base = set(previous_version.assignments) if previous_version else set()
    scoped_keys = {
        (item.access_provider, item.access_name, item.identity_provider, item.identity_identifier)
        for item in review_items
    }
    if mode == "full_replace":
        result: set[GoldenSourceAssignment] = set()
    elif mode == "replace_scope":
        result = {item for item in base if item.key() not in scoped_keys}
    else:
        raise ValueError("mode must be replace_scope or full_replace")
    for item in review_items:
        decision = latest[item.id]
        assignment = GoldenSourceAssignment(
            item.access_provider, item.access_name, item.identity_provider, item.identity_identifier
        )
        if decision.value == DecisionValue.APPROVE:
            result.add(assignment)
        elif decision.value == DecisionValue.REVOKE:
            result.discard(assignment)
    return create_golden_version(
        golden_source,
        result,
        "promoted_campaign",
        [previous_version] if previous_version else [],
        source_campaign_id=campaign.id,
        parent_version_id=previous_version.id if previous_version else None,
    )


def remediation_from_decisions(
    review_items: list[ReviewItem], decisions: list[Decision]
) -> list[RemediationAction]:
    items = {item.id: item for item in review_items}
    actions: list[RemediationAction] = []
    for decision in latest_decisions(decisions).values():
        item = items[decision.review_item_id]
        if decision.value == DecisionValue.REVOKE:
            actions.append(RemediationAction(review_item_id=item.id, action=RemediationActionType.REVOKE))
        elif decision.value == DecisionValue.APPROVE and item.expected and not item.observed:
            actions.append(RemediationAction(review_item_id=item.id, action=RemediationActionType.GRANT))
    return actions


def audit(event_type: str, object_type: str | None = None, object_id: str | None = None) -> AuditEvent:
    return AuditEvent(event_type=event_type, object_type=object_type, object_id=object_id)
