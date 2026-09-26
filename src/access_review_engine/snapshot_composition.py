"""Additive composition of provider snapshots without changing the domain model."""

from __future__ import annotations

from collections.abc import Iterable
from copy import deepcopy
from hashlib import sha256

from access_review_engine.domain import (
    AccessAssignment,
    AccessRelation,
    AccessRelationType,
    AssignmentType,
    Completeness,
    IdentityType,
    Origin,
    Snapshot,
)
from access_review_engine.services import create_snapshot


def _weakest(values: Iterable[str]) -> str:
    ranks = {Completeness.FULL: 0, Completeness.SCOPED: 1, Completeness.UNKNOWN: 2}
    return max(values, key=lambda value: ranks.get(value, 2), default=Completeness.UNKNOWN)


def compose_snapshots(
    snapshots: Iterable[Snapshot], provider_names: list[str], completeness: Iterable[str] = ()
) -> Snapshot:
    selected = [
        snapshot
        for snapshot in snapshots
        if {provider.name for provider in snapshot.providers} & set(provider_names)
    ]
    if not selected:
        raise ValueError("No snapshot is available for the requested providers")
    providers = {
        provider.name: provider
        for snapshot in selected
        for provider in snapshot.providers
        if provider.name in provider_names
    }
    identities = {
        (identity.provider, identity.identifier): identity
        for snapshot in selected
        for identity in snapshot.identities
        if identity.provider in providers
    }
    accesses = {
        (access.provider, access.name): access
        for snapshot in selected
        for access in snapshot.accesses
        if access.provider in providers
    }
    assignments = {
        (
            item.provider,
            item.access_name,
            item.identity_provider,
            item.identity_identifier,
            item.origin_fingerprint,
        ): item
        for snapshot in selected
        for item in snapshot.access_assignments
        if item.provider in providers
    }
    relations = {
        relation.key(): relation
        for snapshot in selected
        for relation in snapshot.access_relations
        if relation.parent_provider in providers and relation.child_provider in providers
    }
    for assignment in assignments.values():
        identity = identities.get((assignment.identity_provider, assignment.identity_identifier))
        if identity is None:
            for snapshot in selected:
                identity = next(
                    (
                        item
                        for item in snapshot.identities
                        if item.provider == assignment.identity_provider
                        and item.identifier == assignment.identity_identifier
                    ),
                    None,
                )
                if identity:
                    identities[(identity.provider, identity.identifier)] = identity
                    break
    assignments = {
        (
            resolved.provider,
            resolved.access_name,
            resolved.identity_provider,
            resolved.identity_identifier,
            resolved.origin_fingerprint,
        ): resolved
        for item in assignments.values()
        for resolved in [_resolve_composite_assignment(item, identities.values(), providers.values())]
    }
    # A provider-local group membership access grants a cross-provider access only
    # when the direct cloud assignment resolved to that exact Workspace group.
    group_accesses = {
        (access.provider, str(access.metadata.get("source_group", "")).casefold()): access
        for access in accesses.values()
        if access.provider in providers and access.metadata.get("membership_role") == "MEMBER"
    }
    for assignment in assignments.values():
        if (
            assignment.provider == assignment.identity_provider
            or assignment.identity_provider not in providers
        ):
            continue
        group_access = group_accesses.get(
            (assignment.identity_provider, assignment.identity_identifier.casefold())
        )
        if group_access is None:
            continue
        seed = "|".join(
            (
                group_access.provider,
                group_access.name,
                assignment.provider,
                assignment.access_name,
                str(AccessRelationType.GRANTS),
            )
        )
        relations["derived:" + sha256(seed.encode()).hexdigest()] = AccessRelation(
            group_access.provider,
            group_access.name,
            assignment.provider,
            assignment.access_name,
            AccessRelationType.GRANTS,
            Origin(
                AssignmentType.INHERITED,
                False,
                True,
                "composite",
                {"derived": True, "source": "cross_provider_group_resolution"},
            ),
            {"derived": True, "cross_provider": True},
            id="derived-cross-provider:" + sha256(seed.encode()).hexdigest(),
        )
    source_ids = sorted(
        {source_id for snapshot in selected for source_id in snapshot.source_import_ids}
    )
    scoped = _weakest(completeness)
    return create_snapshot(
        list(providers.values()),
        list(identities.values()),
        [],
        list(accesses.values()),
        list(assignments.values()),
        source_ids,
        access_relations=list(relations.values()),
        import_scope={"type": "providers", "values": sorted(providers), "completeness": scoped},
    )


def _resolve_composite_assignment(
    assignment: AccessAssignment, identities: Iterable, providers: Iterable = ()
) -> AccessAssignment:
    """Resolve an old provider-local Google principal against identities in the composite.

    Source snapshots remain immutable and retain the original principal evidence. The composed
    snapshot may point the direct assignment at the now-known Workspace identity so graph
    traversal can derive cross-provider access without materializing a direct effective grant.
    """
    principal = assignment.origin.raw.get("principal")
    if not assignment.origin.raw.get("unresolved") or not isinstance(principal, str):
        return assignment
    kind, separator, identifier = principal.partition(":")
    if not separator or kind not in {"user", "group", "serviceAccount"}:
        return assignment
    identity_type = {
        "user": IdentityType.USER_ACCOUNT,
        "group": IdentityType.GROUP,
        "serviceAccount": IdentityType.TECHNICAL_ACCOUNT,
    }[kind]
    wanted = identifier.casefold()
    candidates = []
    for identity in identities:
        if isinstance(identity.metadata, dict) and identity.metadata.get("unresolved"):
            continue
        if identity.type != identity_type:
            continue
        values = [identity.identifier, identity.email]
        if isinstance(identity.metadata, dict):
            values.extend(identity.metadata.get("aliases", []))
        if any(str(value or "").casefold() == wanted for value in values):
            candidates.append(identity)
    provider_types = {provider.name: provider.type for provider in providers}
    preferred_types = {"google_workspace"} if kind in {"user", "group"} else {"gcp_iam"}
    preferred = [item for item in candidates if provider_types.get(item.provider) in preferred_types]
    if preferred:
        candidates = preferred
    unique = {(item.provider, item.identifier): item for item in candidates}
    if len(unique) != 1:
        if len(unique) > 1:
            updated = deepcopy(assignment)
            updated.origin.raw["ambiguous"] = True
            return updated
        return assignment
    identity = next(iter(unique.values()))
    updated = deepcopy(assignment)
    updated.identity_provider = identity.provider
    updated.identity_identifier = identity.identifier
    updated.origin.raw["composite_resolved"] = True
    updated.origin.raw["cross_domain_resolved"] = identity.provider != assignment.provider
    return updated
