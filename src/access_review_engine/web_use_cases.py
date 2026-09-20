"""Application use cases shared by the REST API and future non-CLI clients.

This module deliberately deals in repository payloads at its boundary. Domain decisions and
reconciliation remain in ``application`` and ``services``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from copy import deepcopy
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
from typing import Any

from access_review_engine.application import import_file_to_repository, load_classification_rules
from access_review_engine.campaign_authorization import normalize_campaign_scope
from access_review_engine.domain import Campaign, Finding, GoldenSourceVersion, Snapshot
from access_review_engine.services import compare_snapshot, open_campaign
from access_review_engine.source_mapping import BUSINESS_CONTEXT_METADATA_KEY, connector_business_mapping
from access_review_engine.storage import Repository


@dataclass(frozen=True)
class PreviewSyncResult:
    tables: dict[str, dict[str, int]]
    objects: dict[str, dict[str, int]]
    comparison: dict[str, int]
    collection_incomplete: bool
    access_preview: list[dict[str, object]]
    mapping: dict[str, object]
    persisted: bool = False

    def as_dict(self) -> dict[str, object]:
        return asdict(self)

@dataclass(frozen=True)
class CampaignPreparation:
    """In-memory context shared by campaign preview and opening."""

    snapshot: Snapshot
    golden_version: GoldenSourceVersion | None
    comparison_states: list[dict[str, object]]


def snapshot_collection_scope(repo: Repository, snapshot: Snapshot) -> dict[str, object] | None:
    """Recover the collection boundary that produced an immutable snapshot.

    Snapshot deliberately stores only import identifiers. Campaign comparison must follow those
    identifiers back to their import batches; treating a provider-scoped collection as global would
    turn every uncollected provider into a false ``missing`` result.
    """
    source_ids = set(snapshot.source_import_ids)
    if not source_ids:
        # A legacy snapshot without import references cannot prove that its collection was
        # exhaustive. Keep conclusions inside the providers it contains and mark absence as
        # unknown rather than manufacturing global ``missing`` findings.
        return {
            "type": "providers",
            "values": sorted(provider.name for provider in snapshot.providers),
            "completeness": "unknown",
        }
    imports = [row for row in repo.list_payloads("imports") if str(row.get("id")) in source_ids]
    if not imports:
        # Legacy/incomplete persistence is not authoritative. Being conservative is preferable to
        # certifying false absences.
        return {
            "type": "providers",
            "values": sorted(provider.name for provider in snapshot.providers),
            "completeness": "unknown",
        }
    if len(imports) == 1:
        scope = imports[0].get("scope")
        if isinstance(scope, dict):
            return deepcopy(scope)

    providers: set[str] = set()
    complete = True
    for row in imports:
        scope = row.get("scope") if isinstance(row.get("scope"), dict) else {}
        providers.update(str(value) for value in scope.get("values", []) if value)
        if row.get("provider"):
            providers.add(str(row["provider"]))
        completeness = str(scope.get("completeness") or row.get("completeness") or "unknown")
        complete = complete and completeness == "full"
    return {
        "type": "providers",
        "values": sorted(providers),
        "completeness": "full" if complete else "unknown",
    }


def prepare_campaign_review(
    campaign: Campaign,
    snapshot: Snapshot,
    golden_version: GoldenSourceVersion | None,
    import_scope: dict[str, object] | None = None,
) -> CampaignPreparation:
    """Recompute campaign rows without changing the persisted snapshot."""
    rows = compare_snapshot(snapshot, golden_version, import_scope)
    try:
        scope = normalize_campaign_scope(campaign.scope or {"type": "all"})
    except ValueError as exc:
        raise ValueError(str(exc)) from exc
    if scope["type"] == "providers":
        providers = set(scope["values"])
        rows = [row for row in rows if str(row.get("access_provider")) in providers]
    elif scope["type"] == "accesses":
        selected = {(item["provider"], item["name"]) for item in scope["values"]}
        known = {(access.provider, access.name) for access in snapshot.accesses}
        known.update((str(row.get("access_provider")), str(row.get("access_name"))) for row in rows)
        unknown = selected - known
        if unknown:
            provider, name = sorted(unknown)[0]
            raise ValueError(f"Selected Access was not found in the Snapshot or Golden Source: {provider}/{name}")
        rows = [row for row in rows if (str(row.get("access_provider")), str(row.get("access_name"))) in selected]
    prepared = deepcopy(snapshot)
    prepared.comparison_states = rows
    return CampaignPreparation(prepared, golden_version, rows)


def preview_campaign_review(
    campaign: Campaign,
    snapshot: Snapshot,
    golden_version: GoldenSourceVersion | None,
    fallback_reviewer: object | None = None,
    import_scope: dict[str, object] | None = None,
    preparation: CampaignPreparation | None = None,
) -> dict[str, object]:
    """Resolve reviewers through the same service path as the real open operation."""
    preparation = preparation or prepare_campaign_review(campaign, snapshot, golden_version, import_scope)
    preview_campaign = deepcopy(campaign)
    preview_campaign.allow_unresolved_reviewers = True
    _, items = open_campaign(preview_campaign, preparation.snapshot, fallback_reviewer)  # type: ignore[arg-type]
    unresolved = [{"identity": item.identity_identifier, "identity_provider": item.identity_provider, "access": item.access_name, "access_provider": item.access_provider} for item in items if item.reviewer is None]
    return {"total_review_items": len(items), "resolved_reviewers": len(items) - len(unresolved), "unresolved_reviewers": len(unresolved), "unresolved": unresolved, "comparison_states": preparation.comparison_states}


def list_payloads(
    db_path: str | Path,
    table: str,
    *,
    limit: int = 100,
    offset: int = 0,
    search: str | None = None,
    status: str | None = None,
    provider: str | None = None,
) -> dict[str, object]:
    with Repository(db_path) as repo:
        rows = repo.list_payloads(table)
    filtered = [
        row for row in rows
        if (not search or search.lower() in json.dumps(row, sort_keys=True).lower())
        and (not status or row.get("status") == status)
        and (not provider or row.get("provider") == provider
             or row.get("identity_provider") == provider
             or row.get("access_provider") == provider)
    ]
    return {"items": filtered[offset : offset + limit], "total": len(filtered), "limit": limit, "offset": offset}


def latest_snapshot(db_path: str | Path) -> dict[str, Any] | None:
    with Repository(db_path) as repo:
        rows = repo.list_payloads("snapshots")
    return rows[-1] if rows else None


def preview_import(
    db_path: str | Path,
    input_path: str | Path,
    *,
    provider: str = "openldap",
    classification_rules: str | Path | None = None,
    source_config: dict[str, object] | None = None,
) -> PreviewSyncResult:
    """Run the real import engine against a SQLite backup and discard the backup."""
    source = Path(db_path)
    target_parent = Path(tempfile.mkdtemp(prefix="eare-preview-"))
    target = target_parent / "preview.db"
    before = table_counts(source)
    try:
        backup_if_present(source, target)
        repo = Repository(target)
        try:
            snapshot = import_file_to_repository(
                repo,
                input_path,
                provider_name=provider,
                classification_rules=load_classification_rules(classification_rules),
                source_config=source_config,
            )
        finally:
            repo.close()
        after = table_counts(target)
        changed = {
            table: {"before": before[table], "after": after[table]}
            for table in before
            if before[table] != after[table]
        }
        states: dict[str, int] = {}
        for row in snapshot.comparison_states:
            key = str(row.get("classification", "unknown"))
            states[key] = states.get(key, 0) + 1
        incomplete = any(
            Finding.COLLECTION_INCOMPLETE in row.get("findings", [])
            for row in snapshot.comparison_states
        )
        access_preview: list[dict[str, object]] = []
        for access in snapshot.accesses[:100]:
            context = access.metadata.get(BUSINESS_CONTEXT_METADATA_KEY, {})
            raw_source = {
                str(value.get("attribute")): value.get("value")
                for value in context.values()
                if isinstance(value, dict) and value.get("attribute")
            }
            permission = access.permission.identifier if access.permission else None
            access_preview.append({
                "provider": access.provider,
                "access_name": access.name,
                "display_name": access.display_name,
                "raw_source": raw_source,
                "technical": {
                    "permission": permission,
                    "entitlement": "Member" if str(permission or "").casefold() == "member" else permission,
                    "grant_mechanism": "Group membership" if str(permission or "").casefold() == "member" else "Direct assignment",
                },
                "business_context": context,
            })
        mapping_report: dict[str, object] = {"warning": False, "diagnostics": []}
        if source_config is not None and str(source_config.get("type")) in {"active_directory", "openldap"}:
            kind = str(source_config["type"])
            configured = connector_business_mapping(source_config, kind)
            diagnostics = []
            for field, entry in configured.items():
                if entry["mode"] != "attribute":
                    continue
                available = any(
                    field in access.metadata.get(BUSINESS_CONTEXT_METADATA_KEY, {})
                    for access in snapshot.accesses
                )
                diagnostics.append({
                    "field": field,
                    "attribute": entry.get("attribute"),
                    "status": "available" if available else "unavailable_in_artifact",
                })
            mapping_report = {
                "warning": any(row["status"] == "unavailable_in_artifact" for row in diagnostics),
                "diagnostics": diagnostics,
            }
        return PreviewSyncResult(
            tables=changed,
            objects=object_deltas(source, target),
            comparison=states,
            collection_incomplete=incomplete,
            access_preview=access_preview,
            mapping=mapping_report,
        )
    finally:
        shutil.rmtree(target_parent, ignore_errors=True)


def table_counts(path: str | Path) -> dict[str, int]:
    from access_review_engine.storage import TABLES

    counts = {table: 0 for table in TABLES}
    if not Path(path).exists():
        return counts
    connection = sqlite3.connect(path)
    try:
        for table in counts:
            counts[table] = int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
    finally:
        connection.close()
    return counts


def backup_if_present(source: str | Path, target: Path) -> None:
    if not Path(source).exists():
        return
    source_conn = sqlite3.connect(source)
    target_conn = sqlite3.connect(target)
    try:
        source_conn.backup(target_conn)
    finally:
        target_conn.close()
        source_conn.close()


def object_deltas(before_path: str | Path, after_path: str | Path) -> dict[str, dict[str, int]]:
    from access_review_engine.storage import TABLES

    def records(path: str | Path, table: str) -> dict[str, dict[str, Any]]:
        if not Path(path).exists():
            return {}
        connection = sqlite3.connect(path)
        try:
            rows = connection.execute(f"SELECT id, payload FROM {table}").fetchall()
            return {str(row[0]): json.loads(str(row[1])) for row in rows}
        finally:
            connection.close()

    result: dict[str, dict[str, int]] = {}
    for table in TABLES:
        before = records(before_path, table)
        after = records(after_path, table)
        common = set(before) & set(after)
        counts = {"added": len(set(after) - set(before)), "removed": len(set(before) - set(after)), "updated": 0, "renamed": 0, "disabled": 0, "deleted": 0}
        for object_id in common:
            old, new = before[object_id], after[object_id]
            if old == new:
                continue
            if payload_name(old) != payload_name(new):
                counts["renamed"] += 1
            if old.get("status") != "disabled" and new.get("status") == "disabled":
                counts["disabled"] += 1
            if old.get("status") != "deleted" and new.get("status") == "deleted":
                counts["deleted"] += 1
            counts["updated"] += 1
        if any(counts.values()):
            result[table] = counts
    return result


def payload_name(payload: dict[str, Any]) -> str | None:
    for key in ("name", "identifier", "access_name"):
        if payload.get(key) is not None:
            return str(payload[key])
    return None
