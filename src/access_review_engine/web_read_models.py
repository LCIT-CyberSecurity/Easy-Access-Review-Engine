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


def review_item_view(repo: Repository, row: dict[str, Any]) -> dict[str, Any]:
    decision = _latest_decisions(repo.list_payloads("decisions")).get(str(row.get("id")))
    result = dict(row)
    result["identity"] = {"provider": row.get("identity_provider"), "identifier": row.get("identity_identifier"), "status": row.get("identity_status")}
    result["access"] = {"provider": row.get("access_provider"), "name": row.get("access_name"), "permission": row.get("permission"), "target": row.get("target")}
    result["latest_decision"] = decision
    result["decision_state"] = "decided" if decision else "pending"
    result["decision"] = decision.get("value") if decision else None
    return result


def projected_rows(db_path: str, table: str, *, limit: int, offset: int, search: str | None = None, status: str | None = None, provider: str | None = None) -> dict[str, object]:
    with Repository(db_path) as repo:
        raw = repo.list_payloads(table)
        rows = [review_item_view(repo, item) for item in raw] if table == "review_items" else [dict(item) for item in raw]
        if table == "identities":
            assignments = repo.list_payloads("access_assignments")
            snapshots = repo.list_payloads("snapshots")
            finding_keys = {(item.get("identity_provider"), item.get("identity_identifier")) for snapshot in snapshots for item in snapshot.get("comparison_states", []) if item.get("findings")}
            for row in rows:
                key = (row.get("provider"), row.get("identifier"))
                row["access_count"] = sum(a.get("identity_provider") == key[0] and a.get("identity_identifier") == key[1] for a in assignments)
                row["finding_count"] = int(key in finding_keys)
        if table == "campaigns":
            decisions = _latest_decisions(repo.list_payloads("decisions"))
            items = repo.list_payloads("review_items")
            for row in rows:
                scoped = [item for item in items if item.get("campaign_id") == row.get("id")]
                decided = sum(item.get("id") in decisions for item in scoped)
                row["review_items"] = len(scoped)
                row["pending"] = len(scoped) - decided
                row["progress"] = round(decided / len(scoped) * 100, 1) if scoped else 0
                row["findings_count"] = sum(bool(item.get("findings")) for item in scoped)
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
