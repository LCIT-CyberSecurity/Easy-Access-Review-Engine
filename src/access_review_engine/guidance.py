"""Deterministic, read-only guidance for the EARE Guide.

The engine consumes an already-authorized factual context. It never decides
whether a user may perform an operation; the API builds the context after
applying the same role, scope and campaign filters used by the rest of EARE.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class GuidanceContext:
    role: str
    route: str
    source_count: int = 0
    synchronized_source_count: int = 0
    latest_snapshot: bool = False
    golden_available: bool = False
    open_campaigns: tuple[dict[str, Any], ...] = ()
    pending_reviews: int = 0
    assigned_pending_reviews: int = 0
    assigned_campaign_count: int = 0
    pending_actions: int = 0
    exported_actions: int = 0
    not_completed_actions: int = 0
    completed_actions: int = 0
    open_actions: int = 0
    operator_count: int = 0
    operator_coverage_complete: bool = True
    uncovered_operator_domains: tuple[str, ...] = ()
    setup_checklist: tuple[dict[str, Any], ...] = ()
    username: str = ""
    capabilities: frozenset[str] = field(default_factory=frozenset)
    campaign_readiness: dict[str, Any] | None = None
    unresolved_reviewers: int = 0
    findings_count: int = 0
    allowed_routes: frozenset[str] = field(default_factory=frozenset)


def _recommendation(
    identifier: str,
    category: str,
    title: str,
    description: str,
    reason: str,
    priority: str,
    action_label: str | None = None,
    action_url: str | None = None,
    *,
    status: str = "actionable",
    blocking_reason: str | None = None,
) -> dict[str, Any]:
    return {
        "id": identifier,
        "category": category,
        "title": title,
        "description": description,
        "reason": reason,
        "priority": priority,
        "status": status,
        "action_label": action_label,
        "action_url": action_url,
        "allowed": bool(action_url),
        "blocking_reason": blocking_reason,
        "completion_state": "incomplete" if status in {"actionable", "blocked"} else "complete",
    }


def _page_help(route: str) -> dict[str, Any]:
    pages = {
        "/": {
            "title": "guide.page.overview.title",
            "description": "guide.page.overview.description",
            "topics": [{"id": "next", "question": "guide.question.next", "answer": "guide.answer.next"}, {"id": "readiness", "question": "guide.question.readiness", "answer": "guide.answer.readiness"}],
        },
        "/sources": {
            "title": "guide.page.sources.title",
            "description": "guide.page.sources.description",
            "topics": [{"id": "snapshot", "question": "guide.question.sourceSync", "answer": "guide.answer.snapshot"}, {"id": "next", "question": "guide.question.next", "answer": "guide.answer.next"}],
        },
        "/golden": {
            "title": "guide.page.golden.title",
            "description": "guide.page.golden.description",
            "topics": [{"id": "golden", "question": "guide.question.goldenMeaning", "answer": "guide.answer.goldenMeaning"}, {"id": "next", "question": "guide.question.next", "answer": "guide.answer.next"}],
        },
        "/campaigns": {
            "title": "guide.page.campaigns.title",
            "description": "guide.page.campaigns.description",
            "topics": [{"id": "readiness", "question": "guide.question.campaignReadiness", "answer": "guide.answer.campaignReadiness"}, {"id": "next", "question": "guide.question.next", "answer": "guide.answer.next"}],
        },
        "/reviews": {
            "title": "guide.page.reviews.title",
            "description": "guide.page.reviews.description",
            "topics": [{"id": "review", "question": "guide.question.reviewDecision", "answer": "guide.answer.reviewDecision"}, {"id": "next", "question": "guide.question.next", "answer": "guide.answer.next"}],
        },
        "/actions": {
            "title": "guide.page.actions.title",
            "description": "guide.page.actions.description",
            "topics": [{"id": "remediation", "question": "guide.question.remediation", "answer": "guide.answer.remediation"}, {"id": "next", "question": "guide.question.next", "answer": "guide.answer.next"}],
        },
        "/reports": {
            "title": "guide.page.reports.title",
            "description": "guide.page.reports.description",
            "topics": [{"id": "report", "question": "guide.question.reportMeaning", "answer": "guide.answer.reportMeaning"}, {"id": "next", "question": "guide.question.next", "answer": "guide.answer.next"}],
        },
    }
    selected = pages.get(route)
    if selected is not None:
        return selected
    for prefix, value in pages.items():
        if prefix != "/" and route.startswith(prefix + "/"):
            return value
    return pages["/"]


def build_guidance(context: GuidanceContext) -> dict[str, Any]:
    """Return safe, explainable recommendations for one authorized context."""
    recommendations: list[dict[str, Any]] = []
    role = context.role
    route = context.route

    def add(*args: Any, action_url: str | None = None, **kwargs: Any) -> None:
        if action_url is None or action_url in context.allowed_routes:
            recommendations.append(_recommendation(*args, action_url=action_url, **kwargs))
        else:
            recommendations.append(_recommendation(*args, action_url=None, status="blocked", blocking_reason="guide.authorizationRequired", **kwargs))

    if role == "GROUP_OWNER":
        if context.assigned_pending_reviews:
            add(
                "complete_assigned_reviews", "reviews", "guide.rec.assignedReviews.title",
                "guide.rec.assignedReviews.description", "guide.rec.assignedReviews.reason", "primary",
                "guide.action.openReviews", action_url="/reviews",
            )
        else:
            recommendations.append(_recommendation(
                "no_assigned_reviews", "reviews", "guide.rec.noReviews.title",
                "guide.rec.noReviews.description", "guide.rec.noReviews.reason", "informational",
                status="completed",
            ))
    elif role == "BUSINESS_ADMIN":
        if context.open_actions or context.pending_actions:
            add(
                "review_remediation", "remediation", "guide.reviewRemediation.title",
                "guide.reviewRemediation.description", "guide.reviewRemediation.reason", "primary",
                "guide.action.openActions", action_url="/actions",
            )
        else:
            recommendations.append(_recommendation(
                "no_pending_actions", "remediation", "guide.rec.noActions.title",
                "guide.rec.noActions.description", "guide.rec.noActions.reason", "informational",
                status="completed",
            ))
    elif role == "REMEDIATION_MANAGER":
        if context.open_actions or context.pending_actions:
            add(
                "process_remediation", "remediation", "guide.rec.remediation.title",
                "guide.rec.remediation.description", "guide.rec.remediation.reason", "primary",
                "guide.action.openActions", action_url="/actions",
            )
        else:
            recommendations.append(_recommendation(
                "no_pending_actions", "remediation", "guide.rec.noActions.title",
                "guide.rec.noActions.description", "guide.rec.noActions.reason", "informational",
                status="completed",
            ))
    elif role == "ADMIN":
        if not context.source_count:
            add(
                "configure_sources", "setup", "guide.rec.configureSources.title",
                "guide.rec.configureSources.description", "guide.rec.configureSources.reason", "primary",
                "guide.action.manageSources", action_url="/sources",
            )
        elif not context.latest_snapshot:
            add(
                "collect_snapshot", "setup", "guide.rec.collectSnapshot.title",
                "guide.rec.collectSnapshot.description", "guide.rec.collectSnapshot.reason", "primary",
                "guide.action.openSources", action_url="/sources",
            )
        elif not context.golden_available:
            add(
                "define_expected_state", "golden", "guide.rec.defineExpected.title",
                "guide.rec.defineExpected.description", "guide.rec.defineExpected.reason", "primary",
                "guide.action.openGolden", action_url="/golden",
            )
        elif context.operator_count and context.operator_coverage_complete:
            add(
                "handoff_to_operator", "governance", "guide.rec.handoff.title",
                "guide.rec.handoff.description", "guide.rec.handoff.reason", "primary",
                "guide.action.viewUsers", action_url="/system/users",
            )
            add(
                "admin_prepare_campaign", "governance", "guide.rec.adminCampaign.title",
                "guide.rec.adminCampaign.description", "guide.rec.adminCampaign.reason", "secondary",
                "guide.action.prepareCampaign", action_url="/campaigns/new",
            )
        elif context.operator_count:
            add(
                "complete_operator_coverage", "governance", "guide.rec.operatorCoverage.title",
                "guide.rec.operatorCoverage.description", "guide.rec.operatorCoverage.reason", "primary",
                "guide.action.viewUsers", action_url="/system/users",
            )
            add(
                "admin_prepare_campaign", "governance", "guide.rec.adminCampaign.title",
                "guide.rec.adminCampaign.description", "guide.rec.adminCampaign.reason", "secondary",
                "guide.action.prepareCampaign", action_url="/campaigns/new",
            )
        else:
            add(
                "create_operator", "governance", "guide.rec.createOperator.title",
                "guide.rec.createOperator.description", "guide.rec.createOperator.reason", "primary",
                "guide.action.createOperator", action_url="/system/users",
            )
            add(
                "admin_continue", "governance", "guide.rec.adminContinue.title",
                "guide.rec.adminContinue.description", "guide.rec.adminContinue.reason", "secondary",
                "guide.action.prepareCampaign", action_url="/campaigns/new",
            )
    elif role == "OPERATOR":
        if not context.source_count:
            add(
                "operator_missing_source", "governance", "guide.rec.operatorSource.title",
                "guide.rec.operatorSource.description", "guide.rec.operatorSource.reason", "primary",
                action_url=None,
            )
        elif not context.latest_snapshot:
            add(
                "operator_missing_snapshot", "governance", "guide.rec.operatorSnapshot.title",
                "guide.rec.operatorSnapshot.description", "guide.rec.operatorSnapshot.reason", "primary",
                "guide.action.openSources", action_url="/sources",
            )
        elif not context.golden_available:
            add(
                "operator_missing_golden", "governance", "guide.rec.operatorGolden.title",
                "guide.rec.operatorGolden.description", "guide.rec.operatorGolden.reason", "primary",
                "guide.action.openGolden", action_url="/golden",
            )
        elif context.open_campaigns and (context.pending_reviews or route.startswith("/campaigns")):
            campaign = sorted(
                context.open_campaigns,
                key=lambda item: (
                    str(item.get("pilot", "")).casefold() != context.username.casefold(),
                    not bool(item.get("overdue")),
                    str(item.get("due_at") or "9999-12-31"),
                    not bool(item.get("pending") or item.get("unresolved_reviewers")),
                    str(item.get("opened_at") or ""),
                ),
            )[0]
            action_url = f"/campaigns/{campaign['id']}"
            if action_url in context.allowed_routes:
                recommendations.append(_recommendation(
                    "continue_campaign", "campaign", "guide.rec.continueCampaign.title",
                    "guide.rec.continueCampaign.description", "guide.rec.continueCampaign.reason", "primary",
                    "guide.action.openCampaign", action_url=action_url,
                ))
            else:
                recommendations.append(_recommendation(
                    "campaign_scope_blocked", "campaign", "guide.rec.campaignBlocked.title",
                    "guide.rec.campaignBlocked.description", "guide.rec.campaignBlocked.reason", "attention",
                    status="blocked", blocking_reason="guide.authorizationRequired",
                ))
        else:
            add(
                "prepare_campaign", "campaign", "guide.rec.prepareCampaign.title",
                "guide.rec.prepareCampaign.description", "guide.rec.prepareCampaign.reason", "primary",
                "guide.action.prepareCampaign", action_url="/campaigns/new",
            )

    if context.unresolved_reviewers:
        recommendations.append(_recommendation(
            "unresolved_reviewers", "readiness", "guide.rec.unresolvedReviewers.title",
            "guide.rec.unresolvedReviewers.description", "guide.rec.unresolvedReviewers.reason", "attention",
            status="blocked",
        ))
    if context.findings_count and role in {"ADMIN", "OPERATOR"}:
        add(
            "review_findings", "quality", "guide.rec.findings.title",
            "guide.rec.findings.description", "guide.rec.findings.reason", "secondary",
            "guide.action.openFindings", action_url="/findings",
        )

    return {
        "role": role,
        "route": route,
        "state": {
            "sources": context.source_count,
            "configured_source_count": context.source_count,
            "synchronized_sources": context.synchronized_source_count,
            "synchronized_source_count": context.synchronized_source_count,
            "latest_snapshot": context.latest_snapshot,
            "golden_available": context.golden_available,
            "open_campaigns": len(context.open_campaigns),
            "pending_reviews": context.pending_reviews,
            "assigned_pending_reviews": context.assigned_pending_reviews,
            "assigned_campaign_count": context.assigned_campaign_count,
            "pending_actions": context.pending_actions,
            "pending_actions_count": context.pending_actions,
            "exported_actions": context.exported_actions,
            "not_completed_actions": context.not_completed_actions,
            "completed_actions": context.completed_actions,
            "open_actions": context.open_actions,
            "operator_count": context.operator_count,
            "operator_coverage_complete": context.operator_coverage_complete,
            "uncovered_operator_domains": list(context.uncovered_operator_domains),
            "unresolved_reviewers": context.unresolved_reviewers,
            "findings": context.findings_count,
            "capabilities": sorted(context.capabilities),
            "setup_checklist": list(context.setup_checklist),
        },
        "recommendations": recommendations,
        "page_help": _page_help(route),
        "campaign_readiness": context.campaign_readiness,
        "read_only": True,
    }
