"""Additive composition of provider snapshots without changing the domain model."""

from __future__ import annotations

from collections.abc import Iterable

from access_review_engine.domain import Completeness, Snapshot
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
        (item.provider, item.access_name, item.identity_provider, item.identity_identifier): item
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
