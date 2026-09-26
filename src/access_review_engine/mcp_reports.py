"""Read-only, allowlisted report projection used by MCP.

This module deliberately does not expose repositories, domain objects, metadata, or
report exporters.  It reuses the same row builder as the WebUI and returns only
fields that are already part of the structured campaign report.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from access_review_engine.campaign_authorization import can_access_campaign, campaign_required_providers
from access_review_engine.reporting import (
    access_names_from_snapshot,
    build_report_rows,
    identity_names_from_snapshot,
    report_summary,
)
from access_review_engine.storage import (
    Repository,
    hydrate_campaign,
    hydrate_decision,
    hydrate_review_item,
    hydrate_snapshot,
)

DEFAULT_LIMIT = 25
MAX_LIMIT = 100
MAX_OFFSET = 1_000_000
MAX_FILTER_LENGTH = 200


class ReportNotFound(PermissionError):
    """Used for both missing and unauthorized reports to prevent IDOR disclosure."""


def bounded_page(limit: int = DEFAULT_LIMIT, offset: int = 0) -> tuple[int, int]:
    if not isinstance(limit, int) or not isinstance(offset, int):
        raise ValueError("limit and offset must be integers")
    if limit < 1 or limit > MAX_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_LIMIT}")
    if offset < 0 or offset > MAX_OFFSET:
        raise ValueError(f"offset must be between 0 and {MAX_OFFSET}")
    return limit, offset


def _filter(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > MAX_FILTER_LENGTH:
        raise ValueError("filter is too long")
    return value.strip().casefold() or None


def _safe_text(value: object, max_length: int = 2000) -> str:
    text = "" if value is None else str(value)
    return text[:max_length]


def _safe_row(row: dict[str, object]) -> dict[str, object]:
    """Explicit report allowlist; never serialize row internals wholesale."""
    fields = (
        "owner", "service", "component", "provider", "control_object_type",
        "control_object", "permission", "access", "access_identifier",
        "description", "identity", "identity_identifier", "identity_provider",
        "identity_status", "expected", "observed", "classification", "findings",
        "issue", "observed_description", "action", "action_reason", "decision",
        "reviewer", "comment",
    )
    result: dict[str, object] = {}
    for field in fields:
        value = row.get(field, "")
        if field == "findings":
            result[field] = [_safe_text(item, 500) for item in str(value or "").split(", ") if item]
        else:
            result[field] = _safe_text(value)
    return result


class McpReportService:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path

    def _load(self, principal: dict[str, Any], report_id: str) -> tuple[Any, Any, list[dict[str, object]]]:
        if not isinstance(report_id, str) or not report_id or len(report_id) > 200:
            raise ReportNotFound("report not found")
        with Repository(self.db_path) as repo:
            payload = repo.get_payload("campaigns", report_id)
            if payload is None:
                raise ReportNotFound("report not found")
            campaign = hydrate_campaign(payload)
            raw_snapshot = repo.get_payload("snapshots", campaign.snapshot_id)
            snapshot = hydrate_snapshot(raw_snapshot) if raw_snapshot else None
            raw_items = [item for item in repo.list_payloads("review_items") if item.get("campaign_id") == report_id]
            required = campaign_required_providers(
                campaign.scope,
                snapshot_providers=[item.provider for item in snapshot.providers] if snapshot else (),
                review_items=raw_items,
            )
            if not can_access_campaign(str(principal.get("role", "")), principal.get("scopes", []), required):
                raise ReportNotFound("report not found")
            items = [hydrate_review_item(item) for item in raw_items]
            item_ids = {item.id for item in items}
            decisions = [hydrate_decision(item) for item in repo.list_payloads("decisions") if item.get("review_item_id") in item_ids]
            rows = build_report_rows(
                items,
                decisions,
                identity_names_from_snapshot(snapshot),
                access_names_from_snapshot(snapshot),
            )
            return campaign, snapshot, [_safe_row(row) for row in rows]

    @staticmethod
    def _context(campaign: Any, snapshot: Any) -> dict[str, object]:
        return {
            "id": campaign.id,
            "name": _safe_text(campaign.display_name or campaign.name),
            "status": _safe_text(campaign.status),
            "created_at": _safe_text(campaign.created_at),
            "opened_at": _safe_text(campaign.opened_at),
            "closed_at": _safe_text(campaign.closed_at),
            "due_at": _safe_text(campaign.due_at),
            "snapshot": {
                "id": _safe_text(snapshot.id) if snapshot else None,
                "created_at": _safe_text(snapshot.created_at) if snapshot else None,
                "providers": [
                    {"name": _safe_text(provider.name), "type": _safe_text(provider.type), "display_name": _safe_text(provider.display_name)}
                    for provider in snapshot.providers
                ] if snapshot else [],
                "source_import_ids": [_safe_text(item, 200) for item in snapshot.source_import_ids] if snapshot else [],
            },
        }

    def list_reports(self, principal: dict[str, Any], limit: int = DEFAULT_LIMIT, offset: int = 0) -> dict[str, object]:
        limit, offset = bounded_page(limit, offset)
        reports: list[dict[str, object]] = []
        with Repository(self.db_path) as repo:
            for payload in repo.list_payloads("campaigns"):
                try:
                    campaign, snapshot, _ = self._load(principal, str(payload.get("id", "")))
                except ReportNotFound:
                    continue
                reports.append({
                    "id": _safe_text(campaign.id), "type": "campaign_report",
                    "name": _safe_text(campaign.display_name or campaign.name),
                    "status": _safe_text(campaign.status), "created_at": _safe_text(campaign.created_at),
                    "scope": campaign.scope if campaign.scope.get("type") == "providers" else {"type": campaign.scope.get("type", "all")},
                    "snapshot_id": _safe_text(snapshot.id) if snapshot else None,
                })
        return {"items": reports[offset:offset + limit], "total": len(reports), "limit": limit, "offset": offset}

    def _report(self, principal: dict[str, Any], report_id: str) -> tuple[dict[str, object], list[dict[str, object]]]:
        campaign, snapshot, rows = self._load(principal, report_id)
        return self._context(campaign, snapshot), rows

    def summary(self, principal: dict[str, Any], report_id: str) -> dict[str, object]:
        context, rows = self._report(principal, report_id)
        summary = report_summary(rows)
        summary.update({
            "identity_count": len({(row["identity_provider"], row["identity_identifier"]) for row in rows}),
            "access_count": len({(row["provider"], row["access_identifier"]) for row in rows}),
            "provider_count": len({row["provider"] for row in rows}),
            "finding_counts": dict(Counter(row["classification"] for row in rows)),
        })
        return {"report": context, "summary": summary}

    def _rows(self, principal: dict[str, Any], report_id: str, limit: int, offset: int, **filters: str | None) -> dict[str, object]:
        limit, offset = bounded_page(limit, offset)
        _, rows = self._report(principal, report_id)
        normalized = {key: _filter(value) for key, value in filters.items()}
        filtered = [
            row for row in rows
            if all(value is None or value in _safe_text(row.get(key)).casefold() for key, value in normalized.items())
        ]
        return {"report_id": report_id, "items": filtered[offset:offset + limit], "total": len(filtered), "limit": limit, "offset": offset}

    def details(self, principal: dict[str, Any], report_id: str, limit: int = DEFAULT_LIMIT, offset: int = 0, classification: str | None = None, provider: str | None = None, identity: str | None = None, access: str | None = None) -> dict[str, object]:
        return self._rows(principal, report_id, limit, offset, classification=classification, provider=provider, identity=identity, access=access)

    def findings(self, principal: dict[str, Any], report_id: str, limit: int = DEFAULT_LIMIT, offset: int = 0, classification: str | None = None, provider: str | None = None, identity: str | None = None, access: str | None = None) -> dict[str, object]:
        _, all_rows = self._report(principal, report_id)
        filters = {key: _filter(value) for key, value in {"classification": classification, "provider": provider, "identity": identity, "access": access}.items()}
        matching = [row for row in all_rows if all(value is None or value in _safe_text(row.get(key)).casefold() for key, value in filters.items())]
        items = [item for item in matching if item["classification"] != "expected_and_observed" or item["findings"]]
        limit, offset = bounded_page(limit, offset)
        return {"report_id": report_id, "items": items[offset:offset + limit], "total": len(items), "limit": limit, "offset": offset}

    def decisions(self, principal: dict[str, Any], report_id: str, limit: int = DEFAULT_LIMIT, offset: int = 0, decision: str | None = None) -> dict[str, object]:
        return self._rows(principal, report_id, limit, offset, decision=decision)

    def remediation_summary(self, principal: dict[str, Any], report_id: str, limit: int = DEFAULT_LIMIT, offset: int = 0) -> dict[str, object]:
        context, rows = self._report(principal, report_id)
        revoke = [row for row in rows if row["decision"] == "revoke"]
        pending = [row for row in rows if row["decision"] == "pending"]
        limit, offset = bounded_page(limit, offset)
        return {"report": context, "summary": {"revoke": len(revoke), "pending": len(pending), "approve": sum(row["decision"] == "approve" for row in rows)}, "items": revoke[offset:offset + limit], "total": len(revoke), "limit": limit, "offset": offset}
