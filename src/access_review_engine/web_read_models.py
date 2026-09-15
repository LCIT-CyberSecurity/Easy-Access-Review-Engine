"""Read-only projections used by the WebUI."""
from __future__ import annotations

from typing import Any, Iterable

from access_review_engine.storage import Repository


def _latest_decisions(rows: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for row in sorted(rows, key=lambda item: (str(item.get("created_at", "")), str(item.get("id", "")))):
        review_id = str(row.get("review_item_id", ""))
        if review_id:
            latest[review_id] = row
    return latest


def review_item_view(repo: Repository, row: dict[str, Any], *, latest_decisions: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    decision = (latest_decisions if latest_decisions is not None else _latest_decisions(repo.list_payloads("decisions"))).get(str(row.get("id")))
    result = dict(row)
    result["identity"] = {"provider": row.get("identity_provider"), "identifier": row.get("identity_identifier"), "status": row.get("identity_status")}
    result["access"] = {"provider": row.get("access_provider"), "name": row.get("access_name"), "permission": row.get("permission"), "target": row.get("target")}
    result["latest_decision"] = decision
    result["decision_state"] = "decided" if decision else "pending"
    result["decision"] = decision.get("value") if decision else None
    return result


def projected_rows(db_path: str, table: str, *, limit: int, offset: int, search: str | None = None, status: str | None = None, provider: str | None = None, reviewer_username: str | None = None, allowed_providers: set[str] | None = None) -> dict[str, object]:
    with Repository(db_path) as repo:
        raw = repo.list_payloads(table)
        latest_decisions = _latest_decisions(repo.list_payloads("decisions"))
        rows = [review_item_view(repo, item, latest_decisions=latest_decisions) for item in raw] if table == "review_items" else [dict(item) for item in raw]
        if table == "review_items" and reviewer_username is not None:
            rows = [row for row in rows if (row.get("reviewer") or {}).get("identity") == reviewer_username]
        if table == "remediation_actions" and allowed_providers is not None:
            items = {str(item.get("id")): item for item in repo.list_payloads("review_items")}
            rows = [row for row in rows if items.get(str(row.get("review_item_id")), {}).get("access_provider") in allowed_providers]
        if table == "providers":
            snapshots = repo.list_payloads("snapshots")
            snapshot = snapshots[-1] if snapshots else None
            jobs = _latest_provider_jobs(db_path)
            for row in rows:
                name = str(row.get("name", ""))
                observed = snapshot and next((item for item in snapshot.get("providers", []) if item.get("name") == name), None)
                if observed is None:
                    row.update({"health": "never_synced", "identity_count": 0, "group_count": 0, "access_count": 0, "last_sync": None, "latest_snapshot": None, "latest_job": jobs.get(name)})
                    continue
                identities = [item for item in snapshot.get("identities", []) if item.get("provider") == name]
                groups = [item for item in identities if str(item.get("type", "")).lower() == "group"]
                assignments = [item for item in snapshot.get("access_assignments", []) if item.get("provider") == name]
                job = jobs.get(name)
                health = "failed" if job and job.get("status") == "FAILED" else "healthy"
                row.update({"health": health, "identity_count": len(identities), "group_count": len(groups), "access_count": len(assignments), "last_sync": snapshot.get("created_at"), "latest_snapshot": snapshot.get("id"), "latest_job": job})
        if table == "identities":
            assignments = repo.list_payloads("access_assignments")
            snapshots = repo.list_payloads("snapshots")
            current_states = snapshots[-1].get("comparison_states", []) if snapshots else []
            for row in rows:
                key = (row.get("provider"), row.get("identifier"))
                row["access_count"] = sum(a.get("identity_provider") == key[0] and a.get("identity_identifier") == key[1] for a in assignments)
                row["finding_count"] = sum(len(finding.get("findings", [])) for finding in current_states if (finding.get("identity_provider"), finding.get("identity_identifier")) == key)
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
            rows = [row for row in rows if row.get("status") == status or row.get("decision") == status]
        if provider:
            rows = [row for row in rows if provider in {row.get("provider"), row.get("identity_provider"), row.get("access_provider")}]
        rows.sort(key=lambda item: str(item.get("identifier", item.get("name", item.get("id", "")))).casefold())
        return {"items": rows[offset:offset + limit], "total": len(rows), "limit": limit, "offset": offset}


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
