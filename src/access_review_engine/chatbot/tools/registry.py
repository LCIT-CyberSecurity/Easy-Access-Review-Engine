from __future__ import annotations

from collections.abc import Callable
from typing import Any

from access_review_engine.chatbot.authorization.policy import visible_campaign
from access_review_engine.chatbot.context import AuthorizationContext, UIHints
from access_review_engine.chatbot.security.tool_policy import MAX_RESULT_COUNT
from access_review_engine.guidance import GuidanceContext, build_guidance
from access_review_engine.storage import Repository

Tool = Callable[[dict[str, Any], AuthorizationContext, UIHints], dict[str, Any]]


def _campaign_providers(
    row: dict[str, Any], reviews: list[dict[str, Any]], snapshots: list[dict[str, Any]]
) -> set[str]:
    providers: set[str] = set()
    scope = row.get("scope") if isinstance(row.get("scope"), dict) else {}
    if scope.get("type") == "providers":
        providers.update(str(item) for item in scope.get("values", []))
    relevant = [item for item in reviews if item.get("campaign_id") == row.get("id")]
    for item in relevant:
        providers.update(
            str(item.get(field))
            for field in ("access_provider", "identity_provider")
            if item.get(field)
        )
    if not providers and scope.get("type", "all") == "all":
        snapshot = next(
            (item for item in snapshots if item.get("id") == row.get("snapshot_id")), None
        )
        if snapshot:
            providers.update(
                str(item.get("name")) for item in snapshot.get("providers", []) if item.get("name")
            )
    return providers


def _visible_campaigns(repo: Repository, context: AuthorizationContext) -> list[dict[str, Any]]:
    reviews = repo.list_payloads("review_items")
    snapshots = repo.list_payloads("snapshots")
    result: list[dict[str, Any]] = []
    for row in repo.list_payloads("campaigns"):
        if visible_campaign(context, _campaign_providers(row, reviews, snapshots)):
            result.append(row)
        elif context.role == "GROUP_OWNER" and any(
            item.get("campaign_id") == row.get("id")
            and str((item.get("reviewer") or {}).get("identity", "")).casefold()
            == context.username.casefold()
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
    decisions = {str(row.get("review_item_id")) for row in repo.list_payloads("decisions")}
    actions = repo.list_payloads("remediation_actions")
    if context.role != "ADMIN":
        actions = [
            row
            for row in actions
            if context.can_access_provider(str(row.get("access_provider") or ""))
        ]
    snapshots = [
        x
        for x in repo.list_payloads("snapshots")
        if context.role == "ADMIN"
        or all(
            context.can_access_provider(str(provider.get("name") or ""))
            for provider in x.get("providers", [])
        )
    ]
    golden_sources = [
        row
        for row in repo.list_payloads("golden_sources")
        if context.role == "ADMIN"
        or context.can_access_provider(str(row.get("name") or ""))
    ]
    return {
        "campaigns": len([x for x in campaigns if x.get("status") == "open"]),
        "pending_reviews": sum(1 for x in reviews if str(x.get("id")) not in decisions),
        "open_actions": sum(1 for x in actions if x.get("status") not in {"completed", "exported"}),
        "sources": len(
            [
                x
                for x in repo.list_payloads("providers")
                if context.can_access_provider(str(x.get("name") or ""))
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
    decisions = {str(x.get("review_item_id")): x for x in repo.list_payloads("decisions")}
    return {
        "available": True,
        "id": identifier,
        "name": str(row.get("name") or "Campaign"),
        "status": str(row.get("status") or "unknown"),
        "total_reviews": len(items),
        "pending_reviews": sum(1 for x in items if str(x.get("id")) not in decisions),
        "decided_reviews": sum(1 for x in items if str(x.get("id")) in decisions),
        "reviewer_coverage": len(
            {str(x.get("reviewer") or "") for x in items if x.get("reviewer")}
        ),
        "findings": sum(1 for x in items if x.get("classification")),
        "due_at": row.get("due_at"),
    }


def golden_gaps(
    repo: Repository, args: dict[str, Any], context: AuthorizationContext, hints: UIHints
) -> dict[str, Any]:
    sources = [
        x
        for x in repo.list_payloads("golden_sources")
        if context.role == "ADMIN" or context.can_access_provider(str(x.get("name") or ""))
    ]
    versions = repo.list_payloads("golden_source_versions")
    gaps = {
        "without_owner": 0,
        "without_application": 0,
        "incomplete_business_context": 0,
        "functional_model_not_defined": 0,
    }
    for row in repo.list_payloads("access_assignments"):
        if (
            not context.can_access_provider(str(row.get("provider") or ""))
            and context.role != "ADMIN"
        ):
            continue
        if not row.get("owner") and not row.get("access_owner"):
            gaps["without_owner"] += 1
    for version in versions:
        assignments = [
            assignment
            for assignment in version.get("assignments", [])
            if context.role == "ADMIN"
            or context.can_access_provider(str(assignment.get("provider") or ""))
        ]
        if version.get("completeness") in {"not_defined", "partial"}:
            if context.role == "ADMIN" or assignments:
                gaps["functional_model_not_defined"] += 1
        for assignment in assignments:
            if not assignment.get("application"):
                gaps["without_application"] += 1
            if not assignment.get("business_context"):
                gaps["incomplete_business_context"] += 1
    return {"golden_sources": len(sources), "gaps": gaps}


def review_progress(
    repo: Repository, args: dict[str, Any], context: AuthorizationContext, hints: UIHints
) -> dict[str, Any]:
    allowed_ids = {str(x.get("id")) for x in _visible_campaigns(repo, context)}
    rows = [
        x for x in repo.list_payloads("review_items") if str(x.get("campaign_id")) in allowed_ids
    ]
    decisions = {str(x.get("review_item_id")) for x in repo.list_payloads("decisions")}
    if context.role == "GROUP_OWNER":
        rows = [
            x
            for x in rows
            if str((x.get("reviewer") or {}).get("identity", "")).casefold()
            == context.username.casefold()
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
                if key
                in {"id", "title", "description", "reason", "priority", "status", "action_url"}
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
        "name": name,
        "description": "Read-only authorized EARE projection",
        "parameters": {
            "type": "object",
            "properties": {"campaign_id": {"type": "string"}},
            "additionalProperties": False,
        },
    }
    for name in TOOL_FUNCTIONS
]


def allowed_actions() -> set[str]:
    return {
        "OPEN_GOLDEN",
        "OPEN_CAMPAIGN",
        "OPEN_PENDING_REVIEWS",
        "OPEN_ACTIONS",
        "OPEN_SOURCES",
        "OPEN_REPORTS",
    }
