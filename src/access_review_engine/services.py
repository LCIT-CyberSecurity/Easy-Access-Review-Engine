from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime
from typing import Iterable

from access_review_engine.domain import (
    Access,
    AccessAssignment,
    AuditEvent,
    Campaign,
    CampaignStatus,
    ComparisonState,
    Completeness,
    Decision,
    DecisionValue,
    Finding,
    GoldenSource,
    GoldenSourceAssignment,
    GoldenSourceVersion,
    Identity,
    IdentityStatus,
    IdentityType,
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
    observed_stable: dict[tuple[str, str, str, str], tuple[str, str, str, str] | None] = {}
    assignment_origins: dict[tuple[str, str, str, str], list[AccessAssignment]] = {}
    for assignment in snapshot.access_assignments:
        legacy_key = assignment.comparison_key()
        assignment_origins.setdefault(legacy_key, []).append(assignment)
        stable_key = _observed_stable_key(assignment, accesses, identities)
        if stable_key is None:
            continue
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
        elif expected_key in observed_legacy:
            observed_key = expected_key

        row_key = observed_key or expected_key
        if observed_key is not None:
            matched_observed.add(observed_key)
            classification = (
                ComparisonState.UNKNOWN_DUE_TO_SCOPE
                if _is_incomplete_scope(import_scope)
                else ComparisonState.EXPECTED_AND_OBSERVED
            )
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
    if access_native_id is None and access is not None:
        access_native_id = access.control_object.native_id
    permission_id = access.permission.identifier if access is not None else "member"
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
) -> Snapshot:
    snapshot = Snapshot(
        providers=providers,  # type: ignore[arg-type]
        identities=identities,
        resources=resources,  # type: ignore[arg-type]
        accesses=accesses,
        access_assignments=assignments,
        source_import_ids=source_import_ids,
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
) -> GoldenSourceVersion:
    previous = list(previous_versions)
    version = max((item.version for item in previous), default=0) + 1
    ordered = sorted(set(assignments), key=lambda item: item.key())
    checksum = stable_checksum([asdict(item) for item in ordered])
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
    )


def promote_snapshot(
    golden_source: GoldenSource,
    snapshot: Snapshot,
    previous_versions: Iterable[GoldenSourceVersion] = (),
) -> GoldenSourceVersion:
    identities = {identity_key(identity): identity for identity in snapshot.identities}
    accesses = {access_key(access): access for access in snapshot.accesses}
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
                access_native_id=access.control_object.native_id if access else None,
                access_permission=access.permission.identifier if access else None,
                identity_native_id=identity.native_id if identity else None,
            )
        )
    previous = list(previous_versions)
    parent_id = max(previous, key=lambda item: item.version).id if previous else None
    return create_golden_version(
        golden_source,
        assignments,
        "promoted_observed_snapshot",
        previous,
        source_snapshot_id=snapshot.id,
        parent_version_id=parent_id,
    )


def golden_diff(
    old: GoldenSourceVersion, new: GoldenSourceVersion
) -> list[dict[str, str]]:
    old_keys = {item.key(): item for item in old.assignments}
    new_keys = {item.key(): item for item in new.assignments}
    rows: list[dict[str, str]] = []
    for key in sorted(old_keys.keys() | new_keys.keys()):
        if key in old_keys and key in new_keys:
            status = "unchanged"
        elif key in new_keys:
            status = "added"
        else:
            status = "removed"
        rows.append(
            {
                "status": status,
                "access_provider": key[0],
                "access_name": key[1],
                "identity_provider": key[2],
                "identity_identifier": key[3],
            }
        )
    return rows


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
                control_object=asdict(access.control_object) if access else {},
                permission=asdict(access.permission) if access else {},
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
