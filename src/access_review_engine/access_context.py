"""Read models and persistence helpers for Access business context."""
from __future__ import annotations

from typing import Any, Mapping

from access_review_engine.domain import now_utc
from access_review_engine.source_mapping import BUSINESS_CONTEXT_METADATA_KEY
from access_review_engine.storage import Repository


ENRICHMENT_FIELDS = ("application", "business_permission", "resource", "description", "owner")
MAX_ENRICHMENT_LENGTH = 1000


def access_enrichment(repo: Repository, access_id: str) -> dict[str, Any] | None:
    return repo.get_payload("access_enrichments", access_id)


def save_access_enrichment(
    repo: Repository,
    access_id: str,
    values: Mapping[str, object],
    updated_by: str | None,
) -> dict[str, Any] | None:
    """Replace editable reference fields for one stable internal Access id."""
    if repo.get_payload("accesses", access_id) is None:
        raise ValueError("Access not found")
    unknown = set(values) - set(ENRICHMENT_FIELDS)
    if unknown:
        raise ValueError("Unsupported access information fields: " + ", ".join(sorted(unknown)))
    previous = access_enrichment(repo, access_id) or {}
    fields = {
        field: _clean_value(values.get(field, previous.get(field)))
        for field in ENRICHMENT_FIELDS
    }
    fields = {field: value for field, value in fields.items() if value is not None}
    if not fields:
        repo.delete_ids("access_enrichments", {access_id})
        return None
    timestamp = now_utc()
    record = {
        "id": access_id,
        "access_id": access_id,
        **fields,
        "created_at": previous.get("created_at") or timestamp,
        "updated_at": timestamp,
        "updated_by": updated_by,
    }
    repo.upsert("access_enrichments", record)
    return record


def source_business_context(access: Mapping[str, Any] | None) -> dict[str, dict[str, Any]]:
    metadata = (access or {}).get("metadata")
    if not isinstance(metadata, dict):
        return {}
    context = metadata.get(BUSINESS_CONTEXT_METADATA_KEY)
    if not isinstance(context, dict):
        return {}
    return {
        str(field): dict(value)
        for field, value in context.items()
        if isinstance(value, dict) and value.get("value") not in {None, ""}
    }


def business_context_view(
    access: Mapping[str, Any] | None,
    enrichment: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Keep observed and manual values separate while making conflicts explicit."""
    source = source_business_context(access)
    manual = {
        field: {"value": enrichment[field], "provenance": "manual"}
        for field in ENRICHMENT_FIELDS
        if enrichment and enrichment.get(field) not in {None, ""}
    }
    fields: dict[str, dict[str, Any]] = {}
    for field in (*ENRICHMENT_FIELDS, "display_name"):
        source_value = source.get(field)
        manual_value = manual.get(field)
        if source_value is None and manual_value is None:
            continue
        conflict = bool(
            source_value
            and manual_value
            and str(source_value.get("value", "")).strip().casefold()
            != str(manual_value.get("value", "")).strip().casefold()
        )
        fields[field] = {
            "source": source_value,
            "manual": manual_value,
            "conflict": conflict,
        }
    return {
        "source_context": source,
        "manual_context": manual,
        "fields": fields,
        "has_conflicts": any(bool(value["conflict"]) for value in fields.values()),
    }


def access_context_for_payload(repo: Repository, access: Mapping[str, Any] | None) -> dict[str, Any]:
    access_id = str((access or {}).get("id") or "")
    enrichment = access_enrichment(repo, access_id) if access_id else None
    return business_context_view(access, enrichment)


def _clean_value(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("Access information values must be text")
    cleaned = value.strip()
    if len(cleaned) > MAX_ENRICHMENT_LENGTH:
        raise ValueError("Access information value is too long")
    return cleaned or None
