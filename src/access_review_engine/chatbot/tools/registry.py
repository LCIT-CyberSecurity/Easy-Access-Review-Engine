from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from access_review_engine.campaign_authorization import campaign_required_providers
from access_review_engine.chatbot.authorization.policy import visible_campaign
from access_review_engine.chatbot.context import AuthorizationContext, UIHints
from access_review_engine.chatbot.security.redaction import redact_secrets
from access_review_engine.chatbot.security.tool_policy import (
    MAX_JSON_CHARS,
    MAX_RESULT_COUNT,
    MAX_STRING_CHARS,
)
from access_review_engine.golden_authorization import can_access_golden
from access_review_engine.golden_functional import functional_access_rows
from access_review_engine.guidance import GuidanceContext, build_guidance
from access_review_engine.storage import Repository, hydrate_golden_version

Tool = Callable[[Repository, dict[str, Any], AuthorizationContext, UIHints], dict[str, Any]]


def _campaign_providers(
    row: dict[str, Any], reviews: list[dict[str, Any]], snapshots: list[dict[str, Any]]
) -> set[str]:
    scope = row.get("scope") if isinstance(row.get("scope"), dict) else {}
    relevant = [item for item in reviews if item.get("campaign_id") == row.get("id")]
    snapshot = next((item for item in snapshots if item.get("id") == row.get("snapshot_id")), None)
    return campaign_required_providers(
        scope,
        comparison_states=relevant,
        review_items=relevant,
        snapshot_providers=[item.get("name") for item in (snapshot or {}).get("providers", [])],
    )


def _is_assigned_to(row: dict[str, Any], username: str) -> bool:
    reviewer = row.get("reviewer")
    identity = reviewer.get("identity") if isinstance(reviewer, dict) else reviewer
    return str(identity or "").casefold() == username.casefold()


def _visible_campaigns(repo: Repository, context: AuthorizationContext) -> list[dict[str, Any]]:
    reviews = repo.list_payloads("review_items")
    snapshots = repo.list_payloads("snapshots")
    result: list[dict[str, Any]] = []
    for row in repo.list_payloads("campaigns"):
        if visible_campaign(context, _campaign_providers(row, reviews, snapshots)):
            result.append(row)
        elif context.role == "GROUP_OWNER" and any(
            item.get("campaign_id") == row.get("id") and _is_assigned_to(item, context.username)
            for item in reviews
        ):
            result.append(row)
    return result


def dashboard(
    repo: Repository, args: dict[str, Any], context: AuthorizationContext, hints: UIHints
) -> dict[str, Any]:
    campaigns = _visible_campaigns(repo, context)
    ids = {str(row.get("id")) for row in campaigns}
    reviews = [
        row for row in repo.list_payloads("review_items") if str(row.get("campaign_id")) in ids
    ]
    if context.role == "GROUP_OWNER":
        reviews = [row for row in reviews if _is_assigned_to(row, context.username)]
    decisions = {str(row.get("review_item_id")) for row in repo.list_payloads("decisions")}
    actions = repo.list_payloads("remediation_actions")
    if context.role not in {"ADMIN", "OPERATOR", "BUSINESS_ADMIN", "REMEDIATION_MANAGER"}:
        actions = []
    elif context.role != "ADMIN":
        actions = [
            row
            for row in actions
            if context.can_access_provider(str(row.get("access_provider") or ""))
        ]
    snapshots = []
    if context.role in {"ADMIN", "OPERATOR"}:
        snapshots = [
            x for x in repo.list_payloads("snapshots")
            if context.role == "ADMIN"
            or (
                x.get("providers")
                and all(
                    context.can_access_provider(str(provider.get("name") or ""))
                    for provider in x.get("providers", [])
                )
            )
        ]
    versions = {str(x.get("id")): x for x in repo.list_payloads("golden_source_versions")}
    golden_sources = []
    if context.role in {"ADMIN", "OPERATOR"}:
        golden_sources = [
            row for row in repo.list_payloads("golden_sources")
            if (version := versions.get(str(row.get("active_version_id") or "")))
            and can_access_golden(context.role, context.scopes, [version])
        ]
    return {
        "campaigns": len([x for x in campaigns if x.get("status") == "open"]),
        "pending_reviews": sum(1 for x in reviews if str(x.get("id")) not in decisions),
        "open_actions": sum(1 for x in actions if x.get("status") not in {"completed", "exported"}),
        "sources": len(
            [
                x
                for x in repo.list_payloads("providers")
                if context.role in {"ADMIN", "OPERATOR"}
                and context.can_access_provider(str(x.get("name") or ""))
            ]
        ),
        "snapshots": len(snapshots),
        "golden_sources": len(golden_sources),
        "findings": sum(1 for x in reviews if x.get("classification")),
    }


def campaign_summary(
    repo: Repository, args: dict[str, Any], context: AuthorizationContext, hints: UIHints
) -> dict[str, Any]:
    identifier = str(args.get("campaign_id") or hints.object_id or "")
    row = next(
        (x for x in _visible_campaigns(repo, context) if str(x.get("id")) == identifier), None
    )
    if row is None:
        return {
            "available": False,
            "message": "Cette campagne n'est pas disponible dans votre périmètre.",
        }
    items = [x for x in repo.list_payloads("review_items") if x.get("campaign_id") == identifier]
    if context.role == "GROUP_OWNER":
        items = [x for x in items if _is_assigned_to(x, context.username)]
    decisions = {str(x.get("review_item_id")): x for x in repo.list_payloads("decisions")}
    return {
        "available": True,
        "id": identifier,
        "name": _safe_text(row.get("name") or "Campaign"),
        "status": str(row.get("status") or "unknown"),
        "total_reviews": len(items),
        "pending_reviews": sum(1 for x in items if str(x.get("id")) not in decisions),
        "decided_reviews": sum(1 for x in items if str(x.get("id")) in decisions),
        "reviewer_coverage": len(
            {str(x.get("reviewer") or "") for x in items if x.get("reviewer")}
        ),
        "findings": sum(1 for x in items if x.get("classification")),
        "due_at": _safe_text(row.get("due_at")) if row.get("due_at") else None,
    }


def golden_gaps(
    repo: Repository, args: dict[str, Any], context: AuthorizationContext, hints: UIHints
) -> dict[str, Any]:
    sources = repo.list_payloads("golden_sources")
    versions = {str(x.get("id")): x for x in repo.list_payloads("golden_source_versions")}
    gaps = {
        "without_owner": 0,
        "without_application": 0,
        "incomplete_business_context": 0,
        "functional_model_not_defined": 0,
        "functional_model_partial": 0,
        "functional_rights_undocumented": 0,
    }
    rows: list[dict[str, Any]] = []
    visible_sources = 0
    for source in sources:
        version = versions.get(str(source.get("active_version_id") or ""))
        if not version:
            continue
        hydrated = hydrate_golden_version(version)
        if not can_access_golden(context.role, context.scopes, [hydrated]):
            continue
        visible_sources += 1
        rows.extend(functional_access_rows(repo, hydrated))
    for row in rows:
        if not row.get("access_owner"):
            gaps["without_owner"] += 1
        fields = row.get("business_context_fields") or {}
        if "application" not in fields:
            gaps["without_application"] += 1
        if not fields or row.get("business_context_conflicts"):
            gaps["incomplete_business_context"] += 1
        completeness = str(row.get("completeness") or "not_defined")
        if completeness == "not_defined":
            gaps["functional_model_not_defined"] += 1
        elif completeness == "partial":
            gaps["functional_model_partial"] += 1
        if completeness in {"not_defined", "partial"} and not row.get("functional_rights"):
            gaps["functional_rights_undocumented"] += 1
    return {
        "golden_sources": visible_sources,
        "rows_considered": len(rows),
        "gaps": gaps,
    }


def review_progress(
    repo: Repository, args: dict[str, Any], context: AuthorizationContext, hints: UIHints
) -> dict[str, Any]:
    allowed_ids = {str(x.get("id")) for x in _visible_campaigns(repo, context)}
    rows = [
        x
        for x in repo.list_payloads("review_items")
        if str(x.get("campaign_id")) in allowed_ids
    ]
    decisions = {str(x.get("review_item_id")) for x in repo.list_payloads("decisions")}
    if context.role == "GROUP_OWNER":
        rows = [
            x
            for x in rows
            if _is_assigned_to(x, context.username)
        ]
    return {
        "total": len(rows),
        "pending": sum(1 for x in rows if str(x.get("id")) not in decisions),
        "decided": sum(1 for x in rows if str(x.get("id")) in decisions),
    }


def guidance(
    repo: Repository, args: dict[str, Any], context: AuthorizationContext, hints: UIHints
) -> dict[str, Any]:
    data = dashboard(repo, {}, context, hints)
    result = build_guidance(
        GuidanceContext(
            role=context.role,
            route=hints.route,
            source_count=data["sources"],
            latest_snapshot=bool(data["snapshots"]),
            golden_available=bool(data["golden_sources"]),
            pending_reviews=data["pending_reviews"],
            open_actions=data["open_actions"],
            allowed_routes=frozenset(
                {
                    "/",
                    "/sources",
                    "/golden",
                    "/campaigns",
                    "/reviews",
                    "/actions",
                    "/reports",
                    "/system/users",
                    "/campaigns/new",
                }
            ),
        )
    )
    return {
        "recommendations": [
            {
                key: value
                for key, value in item.items()
                if key in {"id", "title", "description", "reason", "priority", "status"}
            }
            for item in result.get("recommendations", [])
        ][:MAX_RESULT_COUNT]
    }


def page_help(
    repo: Repository, args: dict[str, Any], context: AuthorizationContext, hints: UIHints
) -> dict[str, Any]:
    result = build_guidance(GuidanceContext(role=context.role, route=hints.route))
    return {"page": result.get("page_help", result.get("page")) or {"route": hints.route}}


TOOL_FUNCTIONS: dict[str, Tool] = {
    "get_dashboard_summary": dashboard,
    "get_campaign_summary": campaign_summary,
    "get_golden_gaps": golden_gaps,
    "get_review_progress": review_progress,
    "get_guidance": guidance,
    "get_page_help": page_help,
}
TOOL_SCHEMAS = [
    {
        "type": "function",
        "name": "get_dashboard_summary",
        "description": "Read-only authorized EARE dashboard projection",
        "strict": True,
        "parameters": {
            "type": "object", "properties": {}, "required": [], "additionalProperties": False
        },
    },
    {
        "type": "function",
        "name": "get_campaign_summary",
        "description": "Read-only authorized EARE campaign projection",
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": {"campaign_id": {"type": ["string", "null"]}},
            "required": ["campaign_id"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function",
        "name": "get_golden_gaps",
        "description": "Read-only authorized Golden quality projection",
        "strict": True,
        "parameters": {
            "type": "object", "properties": {}, "required": [], "additionalProperties": False
        },
    },
    {
        "type": "function",
        "name": "get_review_progress",
        "description": "Read-only authorized review progress projection",
        "strict": True,
        "parameters": {
            "type": "object", "properties": {}, "required": [], "additionalProperties": False
        },
    },
    {
        "type": "function",
        "name": "get_guidance",
        "description": "Read-only deterministic EARE guidance",
        "strict": True,
        "parameters": {
            "type": "object", "properties": {}, "required": [], "additionalProperties": False
        },
    },
    {
        "type": "function",
        "name": "get_page_help",
        "description": "Read-only deterministic help for the validated current page",
        "strict": True,
        "parameters": {
            "type": "object", "properties": {}, "required": [], "additionalProperties": False
        },
    },
]


def _safe_text(value: Any) -> str:
    safe, _ = redact_secrets(str(value))
    return safe[:MAX_STRING_CHARS]


def _sanitize_projection(value: Any, max_items: int = MAX_RESULT_COUNT) -> Any:
    if isinstance(value, str):
        safe, _ = redact_secrets(value)
        return safe[:MAX_STRING_CHARS]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            safe_key = str(key)[:MAX_STRING_CHARS]
            if any(token in safe_key.casefold() for token in (
                "password", "secret", "api_key", "apikey", "bearer", "private_key",
                "refresh_token", "access_token", "credential", "client_secret",
            )):
                continue
            result[safe_key] = _sanitize_projection(item, max_items)
        return result
    if isinstance(value, list):
        return [_sanitize_projection(item, max_items) for item in value[:max_items]]
    if isinstance(value, tuple):
        return [_sanitize_projection(item, max_items) for item in value[:max_items]]
    return value


def bound_tool_output(value: dict[str, Any], max_items: int = MAX_RESULT_COUNT) -> dict[str, Any]:
    sanitized = _sanitize_projection(value, max_items)
    encoded = json.dumps(sanitized, ensure_ascii=False, separators=(",", ":"), default=str)
    if len(encoded) > MAX_JSON_CHARS:
        return {
            "available": True,
            "truncated": True,
            "message": "Résultat borné par la politique de sécurité.",
        }
    return sanitized if isinstance(sanitized, dict) else {"available": False}


def allowed_actions(context: AuthorizationContext) -> set[str]:
    actions: set[str] = set()
    if context.role in {"ADMIN", "OPERATOR", "GROUP_OWNER"}:
        actions.add("OPEN_PENDING_REVIEWS")
    if context.role in {"ADMIN", "OPERATOR"}:
        actions |= {"OPEN_GOLDEN", "OPEN_CAMPAIGN", "OPEN_SOURCES", "OPEN_REPORTS"}
    if context.role in {"ADMIN", "OPERATOR", "BUSINESS_ADMIN", "REMEDIATION_MANAGER"}:
        actions.add("OPEN_ACTIONS")
    return actions
