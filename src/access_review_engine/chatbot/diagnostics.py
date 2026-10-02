"""Deterministic product diagnostics exposed as bounded chatbot projections."""
from __future__ import annotations

from collections import Counter
from typing import Any

from access_review_engine.chatbot.context import AuthorizationContext
from access_review_engine.golden_authorization import can_access_golden
from access_review_engine.golden_functional import functional_access_rows
from access_review_engine.storage import (
    Repository,
    hydrate_campaign,
    hydrate_golden_version,
    hydrate_snapshot,
)
from access_review_engine.web_use_cases import (
    prepare_campaign_review,
    preview_campaign_review,
    snapshot_collection_scope,
)

FINDING_EXPLANATIONS: dict[str, str] = {
    "expected_and_observed":
        "L'accès est attendu par la Golden Source et observé dans le snapshot.",
    "unexpected":
        "L'accès est observé dans le snapshot mais n'est pas attendu par la Golden Source.",
    "missing":
        "L'accès est attendu par la Golden Source mais n'est pas observé dans le snapshot.",
    "unknown_due_to_scope":
        "EARE ne peut pas conclure car le périmètre de collecte est incomplet ou inconnu.",
    "no_reference":
        "Aucune référence Golden exploitable n'est disponible pour cet accès.",
}


def explain_finding(classification: object) -> dict[str, str]:
    key = str(classification or "unknown")
    return {
        "classification": key,
        "explanation": FINDING_EXPLANATIONS.get(
            key, "EARE ne dispose pas d'une explication déterministe pour cette catégorie."
        ),
    }


def summarize_findings(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(
        str(row.get("classification"))
        for row in rows
        if row.get("classification")
    )
    return {
        "total": sum(counts.values()),
        "by_classification": dict(sorted(counts.items())),
        "explanations": [
            explain_finding(classification) for classification in sorted(counts)
        ],
    }


def campaign_readiness(
    repo: Repository,
    campaign: dict[str, Any] | None,
    context: AuthorizationContext,
) -> dict[str, Any]:
    if campaign is None:
        return {
            "available": False,
            "message": "Cette campagne n'est pas disponible dans votre périmètre.",
        }
    campaign_id = str(campaign.get("id") or "")
    status = str(campaign.get("status") or "unknown")
    if status != "draft":
        return {
            "available": True,
            "campaign_id": campaign_id,
            "status": status,
            "ready": status == "open",
            "phase": "already_open" if status == "open" else "not_launchable",
            "blockers": [],
            "warnings": [],
        }

    blockers: list[str] = []
    warnings: list[str] = []
    snapshot_id = campaign.get("snapshot_id")
    golden_id = campaign.get("golden_source_version_id")
    raw_snapshot = repo.get_payload("snapshots", str(snapshot_id)) if snapshot_id else None
    raw_golden = repo.get_payload("golden_source_versions", str(golden_id)) if golden_id else None
    if raw_snapshot is None:
        blockers.append("snapshot_unavailable")
    if raw_golden is None:
        blockers.append("golden_unavailable")

    unresolved_reviewers = 0
    if not blockers:
        try:
            assert raw_snapshot is not None
            hydrated_campaign = hydrate_campaign(campaign)
            snapshot = hydrate_snapshot(raw_snapshot)
            golden = hydrate_golden_version(raw_golden) if raw_golden else None
            prepared = prepare_campaign_review(
                hydrated_campaign,
                snapshot,
                golden,
                snapshot_collection_scope(repo, snapshot),
            )
            preview = preview_campaign_review(
                hydrated_campaign,
                snapshot,
                golden,
                preparation=prepared,
            )
            unresolved_value = preview.get("unresolved_reviewers", 0)
            unresolved_reviewers = int(unresolved_value) if isinstance(unresolved_value, int) else 0
            if unresolved_reviewers and not hydrated_campaign.allow_unresolved_reviewers:
                blockers.append("unresolved_reviewers")
            elif unresolved_reviewers:
                warnings.append("unresolved_reviewers_bypassed")
            if any(
                str(row.get("classification")) == "unknown_due_to_scope"
                for row in prepared.comparison_states
            ):
                warnings.append("incomplete_collection_scope")
        except (ValueError, KeyError, TypeError):
            blockers.append("readiness_unavailable")

    return {
        "available": True,
        "campaign_id": campaign_id,
        "status": status,
        "ready": not blockers,
        "blockers": sorted(set(blockers)),
        "warnings": sorted(set(warnings)),
        "reviewers": {"unresolved": unresolved_reviewers},
    }


def golden_quality_summary(
    repo: Repository,
    context: AuthorizationContext,
) -> dict[str, Any]:
    versions = {str(row.get("id")): row for row in repo.list_payloads("golden_source_versions")}
    rows: list[dict[str, Any]] = []
    assignments: list[dict[str, Any]] = []
    visible_sources = 0
    for source in repo.list_payloads("golden_sources"):
        raw_version = versions.get(str(source.get("active_version_id") or ""))
        if not raw_version:
            continue
        version = hydrate_golden_version(raw_version)
        if not can_access_golden(context.role, context.scopes, [version]):
            continue
        visible_sources += 1
        rows.extend(functional_access_rows(repo, version))
        assignments.extend(raw_version.get("assignments", []))

    identities = {
        (str(row.get("provider")), str(row.get("identifier")))
        for row in repo.list_payloads("identities")
    }
    accesses_without_owner = sum(1 for row in rows if not row.get("access_owner"))
    accesses_without_target = sum(
        1
        for row in rows
        if not row.get("access_target")
        and "application" not in (row.get("business_context_fields") or {})
    )
    unknown_identities = sum(
        1 for assignment in assignments
        if (str(assignment.get("identity_provider")), str(assignment.get("identity_identifier")))
        not in identities
    )
    invalid_owners = sum(
        1 for row in rows
        if row.get("access_owner")
        and (str(row.get("owner_provider")), str(row.get("access_owner"))) not in identities
    )
    orphaned_accesses = sum(1 for row in rows if row.get("relation_diagnostics"))
    completeness = Counter(str(row.get("completeness") or "not_defined") for row in rows)
    functional_rights_undocumented = sum(
        1 for row in rows
        if str(row.get("completeness") or "not_defined") in {"not_defined", "partial"}
        and not row.get("functional_rights")
    )
    blockers = {
        "accesses_without_owner": accesses_without_owner,
        "unknown_identities": unknown_identities,
        "invalid_owners": invalid_owners,
        "orphaned_accesses": orphaned_accesses,
    }
    warnings = {
        "accesses_without_target": accesses_without_target,
        "functional_rights_undocumented": functional_rights_undocumented,
    }
    return {
        "golden_sources": visible_sources,
        "total_accesses": len(rows),
        "accesses_without_owner": accesses_without_owner,
        "accesses_without_target": accesses_without_target,
        "unknown_identities": unknown_identities,
        "invalid_owners": invalid_owners,
        "orphaned_accesses": orphaned_accesses,
        "functional_model_defined": completeness.get("complete", 0),
        "functional_model_partial": completeness.get("partial", 0),
        "functional_model_not_defined": completeness.get("not_defined", 0),
        "functional_rights_undocumented": functional_rights_undocumented,
        "blocking_issues": {key: value for key, value in blockers.items() if value},
        "warnings": {key: value for key, value in warnings.items() if value},
        "ready_for_campaign": not any(blockers.values()),
    }
