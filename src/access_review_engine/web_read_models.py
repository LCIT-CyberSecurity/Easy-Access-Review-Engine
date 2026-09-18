"""Read-only projections used by the WebUI."""
from __future__ import annotations

from dataclasses import asdict
from typing import Any, Iterable

from access_review_engine.services import calculate_effective_accesses
from access_review_engine.storage import Repository, hydrate_snapshot


def _latest_decisions(rows: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for row in sorted(rows, key=lambda item: (str(item.get("created_at", "")), str(item.get("id", "")))):
        review_id = str(row.get("review_item_id", ""))
        if review_id:
            latest[review_id] = row
    return latest


def _display_names(repo: Repository) -> tuple[dict[tuple[str, str], str], dict[tuple[str, str], str]]:
    """Map identities and accesses to the names people recognise.

    Collectors identify objects by a stable native id, so screens must not show that id.
    """
    identities = {
        (str(row.get("provider")), str(row.get("identifier"))): str(row.get("display_name") or row.get("identifier") or "")
        for row in repo.list_payloads("identities")
    }
    accesses = {
        (str(row.get("provider")), str(row.get("name"))): str(row.get("display_name") or row.get("name") or "")
        for row in repo.list_payloads("accesses")
    }
    return identities, accesses


def review_item_view(repo: Repository, row: dict[str, Any], *, latest_decisions: dict[str, dict[str, Any]] | None = None, names: tuple[dict[tuple[str, str], str], dict[tuple[str, str], str]] | None = None) -> dict[str, Any]:
    decision = (latest_decisions if latest_decisions is not None else _latest_decisions(repo.list_payloads("decisions"))).get(str(row.get("id")))
    identity_names, access_names = names if names is not None else _display_names(repo)
    result = dict(row)
    identity_key = (str(row.get("identity_provider")), str(row.get("identity_identifier")))
    access_key = (str(row.get("access_provider")), str(row.get("access_name")))
    result["identity_display_name"] = identity_names.get(identity_key) or row.get("identity_identifier")
    result["access_display_name"] = access_names.get(access_key) or row.get("access_name")
    result["identity"] = {"provider": row.get("identity_provider"), "identifier": row.get("identity_identifier"), "status": row.get("identity_status"), "display_name": result["identity_display_name"]}
    result["access"] = {"provider": row.get("access_provider"), "name": row.get("access_name"), "display_name": result["access_display_name"], "permission": row.get("permission"), "target": row.get("target")}
    result["latest_decision"] = decision
    result["decision_state"] = "decided" if decision else "pending"
    result["decision"] = decision.get("value") if decision else None
    return result


def _latest_snapshot_for_provider(
    snapshots: list[dict[str, Any]], provider: str
) -> dict[str, Any] | None:
    """Return the newest snapshot that actually covers one provider."""
    covered = [
        snapshot
        for snapshot in snapshots
        if any(str(item.get("name")) == provider for item in snapshot.get("providers", []))
    ]
    return max(
        covered,
        key=lambda snapshot: (str(snapshot.get("created_at") or ""), str(snapshot.get("id") or "")),
        default=None,
    )


def _add_review_provenance(
    repo: Repository, rows: list[dict[str, Any]]
) -> None:
    """Project immutable campaign-snapshot paths without changing ReviewItem persistence."""
    campaigns = {str(row.get("id")): row for row in repo.list_payloads("campaigns")}
    snapshots = {str(row.get("id")): row for row in repo.list_payloads("snapshots")}
    evaluations: dict[str, dict[tuple[str, str, str, str], dict[str, Any]]] = {}
    for row in rows:
        campaign = campaigns.get(str(row.get("campaign_id")), {})
        snapshot_id = str(campaign.get("snapshot_id") or "")
        payload = snapshots.get(snapshot_id)
        if not payload or snapshot_id in evaluations:
            continue
        required = {"providers", "identities", "resources", "accesses", "access_assignments", "source_import_ids", "id", "created_at", "checksum"}
        if not required.issubset(payload):
            evaluations[snapshot_id] = {}
            continue
        snapshot = hydrate_snapshot(payload)
        effective = calculate_effective_accesses(
            snapshot.access_assignments,
            snapshot.access_relations,
            snapshot.accesses,
        ).effective_accesses
        evaluations[snapshot_id] = {
            item.key(): asdict(item)
            for item in effective
        }
    for row in rows:
        campaign = campaigns.get(str(row.get("campaign_id")), {})
        snapshot_id = str(campaign.get("snapshot_id") or "")
        key = (
            str(row.get("identity_provider")),
            str(row.get("identity_identifier")),
            str(row.get("access_provider")),
            str(row.get("access_name")),
        )
        effective = evaluations.get(snapshot_id, {}).get(key)
        row["direct"] = bool(effective and effective.get("direct"))
        row["paths"] = list(effective.get("paths", [])) if effective else []


def _is_empty(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


def cell_text(value: Any) -> str:
    """The text a column shows, so filtering matches what the reader sees."""
    if value is None:
        return ""
    if isinstance(value, dict):
        for key in ("display_name", "identifier", "name", "identity"):
            if value.get(key):
                return str(value[key])
        return " ".join(cell_text(item) for item in value.values())
    if isinstance(value, list):
        return " ".join(cell_text(item) for item in value)
    return str(value)


def apply_field_filters(rows: list[dict[str, Any]], filters: dict[str, str] | None) -> list[dict[str, Any]]:
    """Keep the rows whose column contains what was typed under that column."""
    for field, value in (filters or {}).items():
        needle = str(value).strip().casefold()
        if not needle:
            continue
        rows = [row for row in rows if needle in cell_text(row.get(field)).casefold()]
    return rows


def _sort_key(row: dict[str, Any], field: str) -> tuple[float, str]:
    """Order one column, comparing numbers as numbers and text case-insensitively."""
    value = row.get(field)
    if isinstance(value, bool) or isinstance(value, (int, float)):
        return (float(value), "")
    return (0.0, str(value).casefold())


def sorted_rows(rows: list[dict[str, Any]], field: str, order: str | None) -> list[dict[str, Any]]:
    """Sort on a column, always keeping rows without a value at the end."""
    present = [row for row in rows if not _is_empty(row.get(field))]
    missing = [row for row in rows if _is_empty(row.get(field))]
    present.sort(key=lambda item: _sort_key(item, field), reverse=str(order).lower() == "desc")
    return present + missing


def review_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts a reviewer acts on: how much is left, of what kind, and what carries a finding."""
    decided = sum(1 for row in rows if row.get("decision"))
    classification: dict[str, int] = {}
    decision: dict[str, int] = {}
    for row in rows:
        key = str(row.get("classification") or "unknown")
        classification[key] = classification.get(key, 0) + 1
        if row.get("decision"):
            value = str(row["decision"])
            decision[value] = decision.get(value, 0) + 1
    return {
        "total": len(rows),
        "decided": decided,
        "pending": len(rows) - decided,
        "with_findings": sum(1 for row in rows if row.get("findings")),
        "classification": classification,
        "decision": decision,
    }


def projected_rows(db_path: str, table: str, *, limit: int, offset: int, search: str | None = None, status: str | None = None, provider: str | None = None, reviewer_username: str | None = None, allowed_providers: set[str] | None = None, campaign: str | None = None, sort: str | None = None, order: str | None = None, classification: str | None = None, filters: dict[str, str] | None = None) -> dict[str, object]:
    with Repository(db_path) as repo:
        raw = repo.list_payloads(table)
        latest_decisions = _latest_decisions(repo.list_payloads("decisions"))
        names = _display_names(repo) if table in {"review_items", "remediation_actions"} else None
        rows = [review_item_view(repo, item, latest_decisions=latest_decisions, names=names) for item in raw] if table == "review_items" else [dict(item) for item in raw]
        if table == "remediation_actions":
            review_items = {str(item.get("id")): item for item in repo.list_payloads("review_items")}
            campaign_names = {
                str(item.get("id")): str(item.get("display_name") or item.get("name") or "")
                for item in repo.list_payloads("campaigns")
            }
            identity_names, access_names = names or ({}, {})
            for row in rows:
                review_item = review_items.get(str(row.get("review_item_id")), {})
                for key in ("campaign_id", "identity_identifier", "identity_provider", "access_name", "access_provider", "target", "permission", "description"):
                    if key not in row and key in review_item:
                        row[key] = review_item[key]
                row.setdefault("identity_display_name", identity_names.get((str(row.get("identity_provider")), str(row.get("identity_identifier")))) or row.get("identity_identifier"))
                row.setdefault("access_display_name", access_names.get((str(row.get("access_provider")), str(row.get("access_name")))) or row.get("access_name"))
                row["campaign_name"] = campaign_names.get(str(row.get("campaign_id"))) or row.get("campaign_id")
                decision = latest_decisions.get(str(row.get("review_item_id")))
                if decision is not None:
                    row["decision"] = decision.get("value")
                    row["comment"] = decision.get("comment")
                    row["decided_by"] = decision.get("decided_by")
                    row["decided_at"] = decision.get("created_at")
        if table == "review_items" and reviewer_username is not None:
            rows = [row for row in rows if (row.get("reviewer") or {}).get("identity") == reviewer_username]
        if campaign and table == "review_items":
            rows = [row for row in rows if row.get("campaign_id") == campaign]
        if table == "review_items":
            _add_review_provenance(repo, rows)
        if campaign and table == "remediation_actions":
            items = {str(item.get("id")): item for item in repo.list_payloads("review_items")}
            rows = [row for row in rows if items.get(str(row.get("review_item_id")), {}).get("campaign_id") == campaign]
        if table == "remediation_actions" and allowed_providers is not None:
            rows = [row for row in rows if row.get("access_provider") in allowed_providers]
        if table == "providers":
            snapshots = repo.list_payloads("snapshots")
            jobs = _latest_provider_jobs(db_path)
            for row in rows:
                name = str(row.get("name", ""))
                snapshot = _latest_snapshot_for_provider(snapshots, name)
                observed = snapshot and next((item for item in snapshot.get("providers", []) if item.get("name") == name), None)
                if observed is None:
                    job = jobs.get(name)
                    health = "failed" if job and job.get("status") == "FAILED" else "never_synced"
                    row.update({"health": health, "identity_count": 0, "group_count": 0, "access_count": 0, "last_sync": None, "latest_snapshot": None, "latest_job": job})
                    continue
                identities = [item for item in snapshot.get("identities", []) if item.get("provider") == name]
                groups = [item for item in identities if str(item.get("type", "")).lower() == "group"]
                assignments = [item for item in snapshot.get("access_assignments", []) if item.get("provider") == name]
                accesses = [item for item in snapshot.get("accesses", []) if item.get("provider") == name]
                job = jobs.get(name)
                job_is_newer = bool(
                    job
                    and str(job.get("created_at") or "") >= str(snapshot.get("created_at") or "")
                )
                health = "failed" if job_is_newer and job.get("status") == "FAILED" else "healthy"
                access_count = len(accesses) if "accesses" in snapshot else len({
                    (item.get("provider"), item.get("access_name")) for item in assignments
                })
                row.update({"health": health, "identity_count": len(identities), "group_count": len(groups), "access_count": access_count, "last_sync": snapshot.get("created_at"), "latest_snapshot": snapshot.get("id"), "latest_job": job})
        if table == "snapshots":
            for row in rows:
                row["assignment_count"] = len(row.get("access_assignments", []))
                row["provider_count"] = len(row.get("providers", []))
        if table == "identities":
            assignments = repo.list_payloads("access_assignments")
            snapshots = repo.list_payloads("snapshots")
            for row in rows:
                key = (row.get("provider"), row.get("identifier"))
                snapshot = _latest_snapshot_for_provider(snapshots, str(row.get("provider") or ""))
                current_states = snapshot.get("comparison_states", []) if snapshot else []
                row["access_count"] = sum(a.get("identity_provider") == key[0] and a.get("identity_identifier") == key[1] for a in assignments)
                row["finding_count"] = sum(len(finding.get("findings", [])) for finding in current_states if (finding.get("identity_provider"), finding.get("identity_identifier")) == key)
        if table == "accesses":
            assignments = repo.list_payloads("access_assignments")
            snapshots = repo.list_payloads("snapshots")
            for row in rows:
                key = (row.get("provider"), row.get("name"))
                snapshot = _latest_snapshot_for_provider(snapshots, str(row.get("provider") or ""))
                current_states = snapshot.get("comparison_states", []) if snapshot else []
                row["assignment_count"] = sum(
                    assignment.get("provider") == key[0]
                    and assignment.get("access_name") == key[1]
                    for assignment in assignments
                )
                row["holder_count"] = len({
                    (assignment.get("identity_provider"), assignment.get("identity_identifier"))
                    for assignment in assignments
                    if assignment.get("provider") == key[0]
                    and assignment.get("access_name") == key[1]
                })
                row["finding_count"] = sum(
                    len(state.get("findings", []))
                    for state in current_states
                    if (state.get("access_provider"), state.get("access_name")) == key
                )
        if table == "campaigns":
            items = repo.list_payloads("review_items")
            for row in rows:
                scoped = [item for item in items if item.get("campaign_id") == row.get("id")]
                decisions = [latest_decisions.get(str(item.get("id"))) for item in scoped]
                decided = sum(decision is not None for decision in decisions)
                row["review_items"] = len(scoped)
                row["pending"] = len(scoped) - decided
                row["approved"] = sum(bool(decision and decision.get("value") == "approve") for decision in decisions)
                row["revoked"] = sum(bool(decision and decision.get("value") == "revoke") for decision in decisions)
                row["not_applicable"] = sum(bool(decision and decision.get("value") == "not_applicable") for decision in decisions)
                row["progress"] = round(decided / len(scoped) * 100, 1) if scoped else 0
                row["findings_count"] = sum(len(item.get("findings", [])) for item in scoped)
                row["reviewer_resolution"] = {"resolved": sum(item.get("reviewer") is not None for item in scoped), "unresolved": sum(item.get("reviewer") is None for item in scoped)}
        if search:
            needle = search.casefold()
            rows = [row for row in rows if needle in _search_text(row).casefold()]
        if status:
            if table == "review_items" and status == "pending":
                rows = [row for row in rows if row.get("latest_decision") is None]
            else:
                rows = [row for row in rows if row.get("status") == status or row.get("decision") == status or (table == "identities" and row.get("type") == status)]
        if provider:
            rows = [row for row in rows if provider in {row.get("provider"), row.get("identity_provider"), row.get("access_provider")}]
        if classification:
            rows = [row for row in rows if row.get("classification") == classification]
        rows = apply_field_filters(rows, filters)
        summary = review_summary(rows) if table == "review_items" else None
        if sort and any(sort in row for row in rows):
            rows = sorted_rows(rows, sort, order)
        elif table == "review_items":
            rows.sort(
                key=lambda item: (
                    item.get("latest_decision") is not None,
                    str(item.get("identity_display_name") or item.get("identity_identifier") or "").casefold(),
                    str(item.get("access_display_name") or item.get("access_name") or "").casefold(),
                )
            )
        else:
            rows.sort(key=lambda item: str(item.get("identifier", item.get("name", item.get("id", "")))).casefold())
        result: dict[str, object] = {"items": rows[offset:offset + limit], "total": len(rows), "limit": limit, "offset": offset, "sort": sort or "", "order": (order or "asc").lower()}
        if summary is not None:
            result["summary"] = summary
        return result


def _search_text(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(_search_text(item) for item in value.values())
    if isinstance(value, list):
        return " ".join(_search_text(item) for item in value)
    return str(value or "")


def _latest_provider_jobs(db_path: str) -> dict[str, dict[str, Any]]:
    """Return the latest web job for each provider without creating job rows."""
    import sqlite3
    try:
        with sqlite3.connect(db_path) as conn:
            rows = conn.execute(
                "SELECT id, status, progress, created_at, result FROM web_jobs "
                "WHERE kind = 'sync' ORDER BY created_at, id"
            ).fetchall()
    except sqlite3.OperationalError:
        return {}
    latest: dict[str, dict[str, Any]] = {}
    for job_id, status, progress, created_at, result in rows:
        provider = None
        if result:
            try:
                provider = __import__("json").loads(result).get("provider")
            except (TypeError, ValueError, AttributeError):
                provider = None
        if provider:
            latest[str(provider)] = {"id": job_id, "status": status, "progress": progress, "created_at": created_at}
    return latest
