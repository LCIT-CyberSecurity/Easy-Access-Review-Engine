"""Bounded read-only semantic queries over authorized EARE projections."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from access_review_engine.chatbot.authorization.policy import visible_campaign
from access_review_engine.chatbot.context import AuthorizationContext, UIHints
from access_review_engine.chatbot.security.tool_policy import MAX_RESULT_COUNT
from access_review_engine.golden_authorization import can_access_golden
from access_review_engine.golden_functional import functional_access_rows
from access_review_engine.perimeters import path as perimeter_path
from access_review_engine.storage import Repository, hydrate_golden_version


def _limit(args: dict[str, Any]) -> int:
    value = args.get("limit", MAX_RESULT_COUNT)
    return min(MAX_RESULT_COUNT, max(1, int(value)))


def _operational(context: AuthorizationContext) -> bool:
    return context.role in {"ADMIN", "OPERATOR"}


def _provider_allowed(context: AuthorizationContext, provider: object) -> bool:
    return bool(provider) and context.can_access_provider(str(provider))


def _campaign_providers(row: dict[str, Any], repo: Repository) -> set[str]:
    from access_review_engine.chatbot.tools.registry import _campaign_providers as resolve

    return resolve(
        row,
        repo.list_payloads("review_items"),
        repo.list_payloads("snapshots"),
    )


def _reviewer_name(row: dict[str, Any]) -> str:
    reviewer = row.get("reviewer")
    return str(reviewer.get("identity") if isinstance(reviewer, dict) else reviewer or "")


def _visible_campaign_rows(repo: Repository, context: AuthorizationContext) -> list[dict[str, Any]]:
    reviews = repo.list_payloads("review_items")
    rows: list[dict[str, Any]] = []
    for campaign in repo.list_payloads("campaigns"):
        if visible_campaign(context, _campaign_providers(campaign, repo)):
            rows.append(campaign)
        elif context.role == "GROUP_OWNER" and any(
            item.get("campaign_id") == campaign.get("id")
            and _reviewer_name(item).casefold() == context.username.casefold()
            for item in reviews
        ):
            rows.append(campaign)
    return rows


def _perimeters(
    repo: Repository, object_type: str, object_id: object
) -> dict[str, list[dict[str, str]]]:
    result: dict[str, list[dict[str, str]]] = {
        "organizations": [],
        "information_systems": [],
    }
    for assignment in repo.list_payloads("scope_assignments"):
        if assignment.get("object_type") != object_type or str(assignment.get("object_id")) != str(
            object_id
        ):
            continue
        kind = str(assignment.get("scope_type") or "")
        key = "organizations" if kind == "organization" else "information_systems"
        if kind not in {"organization", "information_system"}:
            continue
        identifier = str(assignment.get("scope_id") or "")
        table = "organizations" if kind == "organization" else "information_systems"
        row = repo.get_payload(table, identifier)
        if row:
            result[key].append({"id": identifier, "name": str(row.get("name") or identifier)})
    return result


def _matches_perimeters(row: dict[str, Any], args: dict[str, Any]) -> bool:
    raw_perimeters = row.get("perimeters")
    perimeters: dict[str, Any] = raw_perimeters if isinstance(raw_perimeters, dict) else {}
    for argument, key in (
        ("organization_ids", "organizations"),
        ("information_system_ids", "information_systems"),
    ):
        requested = {str(value) for value in args.get(argument, [])}
        if requested and not requested.intersection(
            str(item.get("id")) for item in perimeters.get(key, []) if isinstance(item, dict)
        ):
            return False
    return True


def _visible_golden_rows(repo: Repository, context: AuthorizationContext) -> list[dict[str, Any]]:
    versions = {str(row.get("id")): row for row in repo.list_payloads("golden_source_versions")}
    result: list[dict[str, Any]] = []
    for source in repo.list_payloads("golden_sources"):
        raw = versions.get(str(source.get("active_version_id") or ""))
        if not raw:
            continue
        version = hydrate_golden_version(raw)
        if not can_access_golden(context.role, context.scopes, [version]):
            continue
        for row in functional_access_rows(repo, version):
            result.append({**row, "golden_source_id": source.get("id")})
    return result


def _right_projection(value: object) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    return {
        "target": value.get("target"),
        "capability": value.get("capability_id"),
        "provenance": value.get("provenance"),
        "native_permission": value.get("native_permission"),
    }


def _access_rows(repo: Repository, context: AuthorizationContext) -> list[dict[str, Any]]:
    if not _operational(context):
        return []
    golden = {
        (str(row.get("access_provider")), str(row.get("access_name"))): row
        for row in _visible_golden_rows(repo, context)
    }
    observed = [
        row
        for row in repo.list_payloads("accesses")
        if _provider_allowed(context, row.get("provider"))
    ]
    by_key = {(str(row.get("provider")), str(row.get("name"))): row for row in observed}
    keys = sorted(set(by_key) | set(golden))
    result: list[dict[str, Any]] = []
    for key in keys:
        access = by_key.get(key, {})
        model = golden.get(key, {})
        access_id = access.get("id") or f"{key[0]}:{key[1]}"
        permission = access.get("permission")
        native_permission = (
            permission.get("identifier") if isinstance(permission, dict) else permission
        )
        rights = [
            projected
            for item in model.get("functional_rights", [])
            if (projected := _right_projection(item)) is not None
        ]
        capabilities = sorted(
            {str(item.get("capability")) for item in rights if item.get("capability")}
        )
        raw_metadata = access.get("metadata")
        metadata: dict[str, Any] = raw_metadata if isinstance(raw_metadata, dict) else {}
        owner = model.get("access_owner")
        if not owner and isinstance(access.get("access_owner"), dict):
            owner = access["access_owner"].get("identity")
        result.append(
            {
                "id": str(access_id),
                "name": key[1],
                "display_name": access.get("display_name")
                or model.get("access_display_name")
                or key[1],
                "provider": key[0],
                "description": access.get("description") or model.get("access_description"),
                "owner": owner,
                "access_type": (
                    (access.get("control_object") or {}).get("type")
                    if isinstance(access.get("control_object"), dict)
                    else model.get("access_type")
                ),
                "completeness": str(model.get("completeness") or "not_defined"),
                "permissions": [native_permission] if native_permission else [],
                "functional_rights": rights[:MAX_RESULT_COUNT],
                "capabilities": capabilities,
                "target": access.get("target") or model.get("access_target"),
                "provenance": model.get("source_provenance") or "observed",
                "privileged": bool(metadata.get("privileged")) or "admin" in capabilities,
                "perimeters": _perimeters(repo, "access", access_id),
            }
        )
    return result


def _filter_accesses(rows: list[dict[str, Any]], args: dict[str, Any]) -> list[dict[str, Any]]:
    text = str(args.get("text") or "").casefold()
    result: list[dict[str, Any]] = []
    for row in rows:
        haystack = json.dumps(row, ensure_ascii=False, default=str).casefold()
        if text and text not in haystack:
            continue
        scalar_filters = {
            "provider": "provider",
            "owner": "owner",
            "completeness": "completeness",
            "provenance": "provenance",
            "access_type": "access_type",
        }
        if any(
            args.get(argument) is not None
            and str(row.get(field) or "").casefold() != str(args[argument]).casefold()
            for argument, field in scalar_filters.items()
        ):
            continue
        if args.get("permission") and str(args["permission"]).casefold() not in {
            str(item).casefold() for item in row["permissions"]
        }:
            continue
        if args.get("owner_state") == "missing" and row.get("owner"):
            continue
        if args.get("owner_state") == "defined" and not row.get("owner"):
            continue
        if args.get("capability") and str(args["capability"]) not in row["capabilities"]:
            continue
        if (
            args.get("target")
            and str(args["target"]).casefold()
            not in json.dumps(row.get("target"), ensure_ascii=False, default=str).casefold()
        ):
            continue
        if args.get("privileged") is not None and row["privileged"] is not args["privileged"]:
            continue
        if not _matches_perimeters(row, args):
            continue
        result.append(row)
    return result


def search_authorized_accesses(
    repo: Repository, args: dict[str, Any], context: AuthorizationContext, hints: UIHints
) -> dict[str, Any]:
    rows = _filter_accesses(_access_rows(repo, context), args)
    limit = _limit(args)
    providers = sorted({str(row["provider"]) for row in rows if row.get("provider")})
    return {
        "items": rows[:limit],
        "count": len(rows),
        "truncated": len(rows) > limit,
        "providers": providers[:MAX_RESULT_COUNT],
        "provider_count": len(providers),
        "providers_truncated": len(providers) > MAX_RESULT_COUNT,
    }


def get_authorized_access(
    repo: Repository, args: dict[str, Any], context: AuthorizationContext, hints: UIHints
) -> dict[str, Any]:
    identifier = str(args.get("access_id") or "")
    row = next((item for item in _access_rows(repo, context) if item["id"] == identifier), None)
    return {"available": row is not None, "item": row}


def _provider_posture(repo: Repository, provider: str) -> dict[str, Any]:
    snapshots = [
        snapshot
        for snapshot in repo.list_payloads("snapshots")
        if isinstance(snapshot.get("authentication_posture"), dict)
        and str(snapshot["authentication_posture"].get("provider") or "") == provider
    ]
    latest = max(snapshots, key=lambda item: str(item.get("created_at") or ""), default=None)
    posture = latest.get("authentication_posture") if latest else None
    if not isinstance(posture, dict):
        return {"state": "not_collected", "controls": {}}
    controls = posture.get("controls") if isinstance(posture.get("controls"), dict) else {}
    completeness = str(posture.get("completeness") or "unknown")
    state = "collected" if controls else "not_collected"
    if completeness in {"unknown", "not_collected"} and not controls:
        state = "not_collected"
    return {"state": state, "completeness": completeness, "controls": controls}


def _identity_rows(repo: Repository, context: AuthorizationContext) -> list[dict[str, Any]]:
    if not _operational(context):
        return []
    accesses = {item["id"]: item for item in _access_rows(repo, context)}
    access_by_key = {(item["provider"], item["name"]): item for item in accesses.values()}
    assignments = [
        row
        for row in repo.list_payloads("access_assignments")
        if _provider_allowed(context, row.get("provider"))
        and _provider_allowed(context, row.get("identity_provider"))
    ]
    result: list[dict[str, Any]] = []
    for identity in repo.list_payloads("identities"):
        provider = str(identity.get("provider") or "")
        if not _provider_allowed(context, provider):
            continue
        identifier = str(identity.get("identifier") or "")
        assigned: list[dict[str, Any]] = []
        for assignment in assignments:
            if (
                str(assignment.get("identity_provider")) != provider
                or str(assignment.get("identity_identifier")) != identifier
            ):
                continue
            access = access_by_key.get(
                (str(assignment.get("provider")), str(assignment.get("access_name")))
            )
            if access is not None:
                assigned.append(access)
        owner = identity.get("account_owner")
        result.append(
            {
                "id": str(identity.get("id") or f"{provider}:{identifier}"),
                "identifier": identifier,
                "display_name": identity.get("display_name") or identifier,
                "provider": provider,
                "identity_type": str(identity.get("type") or "unknown"),
                "status": str(identity.get("status") or "unknown"),
                "owner": owner.get("identity") if isinstance(owner, dict) else None,
                "accesses": [
                    {"id": item["id"], "name": item["name"], "privileged": item["privileged"]}
                    for item in assigned[:MAX_RESULT_COUNT]
                ],
                "access_count": len(assigned),
                "privileged_access": any(bool(item["privileged"]) for item in assigned),
                "authentication_posture": _provider_posture(repo, provider),
                "perimeters": _perimeters(repo, "identity", identity.get("id")),
            }
        )
    return result


def _filter_identities(rows: list[dict[str, Any]], args: dict[str, Any]) -> list[dict[str, Any]]:
    text = str(args.get("text") or "").casefold()
    result = []
    for row in rows:
        if text and text not in json.dumps(row, ensure_ascii=False, default=str).casefold():
            continue
        for argument, field in (
            ("provider", "provider"),
            ("identity_type", "identity_type"),
            ("status", "status"),
            ("owner", "owner"),
        ):
            if args.get(argument) is not None and str(row.get(field) or "").casefold() != str(
                args[argument]
            ).casefold():
                break
        else:
            if args.get("access_id") and not any(
                item["id"] == args["access_id"] for item in row["accesses"]
            ):
                continue
            if args.get("owner_state") == "missing" and row.get("owner"):
                continue
            if args.get("owner_state") == "defined" and not row.get("owner"):
                continue
            if args.get("access_name") and not any(
                str(args["access_name"]).casefold() in str(item["name"]).casefold()
                for item in row["accesses"]
            ):
                continue
            if (
                args.get("authentication_posture")
                and row["authentication_posture"]["state"] != args["authentication_posture"]
            ):
                continue
            if (
                args.get("privileged_access") is not None
                and row["privileged_access"] is not args["privileged_access"]
            ):
                continue
            if not _matches_perimeters(row, args):
                continue
            result.append(row)
    return result


def search_authorized_identities(
    repo: Repository, args: dict[str, Any], context: AuthorizationContext, hints: UIHints
) -> dict[str, Any]:
    rows = _filter_identities(_identity_rows(repo, context), args)
    limit = _limit(args)
    return {"items": rows[:limit], "count": len(rows), "truncated": len(rows) > limit}


def get_authorized_identity(
    repo: Repository, args: dict[str, Any], context: AuthorizationContext, hints: UIHints
) -> dict[str, Any]:
    identifier = str(args.get("identity_id") or "")
    row = next((item for item in _identity_rows(repo, context) if item["id"] == identifier), None)
    return {"available": row is not None, "item": row}


def _review_rows(repo: Repository, context: AuthorizationContext) -> list[dict[str, Any]]:
    campaign_ids = {str(row.get("id")) for row in _visible_campaign_rows(repo, context)}
    decisions = {str(row.get("review_item_id")): row for row in repo.list_payloads("decisions")}
    result = []
    for row in repo.list_payloads("review_items"):
        if str(row.get("campaign_id")) not in campaign_ids:
            continue
        if (
            context.role == "GROUP_OWNER"
            and _reviewer_name(row).casefold() != context.username.casefold()
        ):
            continue
        decision = decisions.get(str(row.get("id")))
        result.append(
            {
                "id": str(row.get("id")),
                "campaign_id": str(row.get("campaign_id")),
                "identity_provider": row.get("identity_provider"),
                "identity_identifier": row.get("identity_identifier"),
                "access_provider": row.get("access_provider"),
                "access_name": row.get("access_name"),
                "classification": row.get("classification"),
                "status": "decided" if decision else "pending",
                "decision": decision.get("value") if decision else None,
                "findings": row.get("findings", []),
            }
        )
    return result


def search_authorized_reviews(
    repo: Repository, args: dict[str, Any], context: AuthorizationContext, hints: UIHints
) -> dict[str, Any]:
    text = str(args.get("text") or "").casefold()
    rows = [
        row
        for row in _review_rows(repo, context)
        if (not text or text in json.dumps(row, ensure_ascii=False).casefold())
        and (not args.get("provider") or row["access_provider"] == args["provider"])
        and (not args.get("campaign_id") or row["campaign_id"] == args["campaign_id"])
        and (not args.get("classification") or row["classification"] == args["classification"])
        and (not args.get("status") or row["status"] == args["status"])
    ]
    limit = _limit(args)
    return {"items": rows[:limit], "count": len(rows), "truncated": len(rows) > limit}


def get_authorized_review(
    repo: Repository, args: dict[str, Any], context: AuthorizationContext, hints: UIHints
) -> dict[str, Any]:
    identifier = str(args.get("review_id") or hints.object_id or "")
    row = next((item for item in _review_rows(repo, context) if item["id"] == identifier), None)
    return {"available": row is not None, "item": row}


def search_authorized_campaigns(
    repo: Repository, args: dict[str, Any], context: AuthorizationContext, hints: UIHints
) -> dict[str, Any]:
    text = str(args.get("text") or "").casefold()
    rows = []
    for row in _visible_campaign_rows(repo, context):
        providers = sorted(_campaign_providers(row, repo))
        item: dict[str, Any] = {
            "id": str(row.get("id")),
            "name": row.get("display_name") or row.get("name"),
            "status": str(row.get("status") or "unknown"),
            "due_at": row.get("due_at"),
            "providers": providers,
        }
        if text and text not in json.dumps(item, ensure_ascii=False).casefold():
            continue
        if args.get("status") and item["status"] != args["status"]:
            continue
        if args.get("provider") and args["provider"] not in providers:
            continue
        rows.append(item)
    limit = _limit(args)
    return {"items": rows[:limit], "count": len(rows), "truncated": len(rows) > limit}


def get_authorized_campaign(
    repo: Repository, args: dict[str, Any], context: AuthorizationContext, hints: UIHints
) -> dict[str, Any]:
    identifier = str(args.get("campaign_id") or hints.object_id or "")
    row = next(
        (
            {
                "id": str(item.get("id")),
                "name": item.get("display_name") or item.get("name"),
                "status": str(item.get("status") or "unknown"),
                "due_at": item.get("due_at"),
                "providers": sorted(_campaign_providers(item, repo)),
            }
            for item in _visible_campaign_rows(repo, context)
            if str(item.get("id")) == identifier
        ),
        None,
    )
    return {"available": row is not None, "item": row}


def _remediation_rows(repo: Repository, context: AuthorizationContext) -> list[dict[str, Any]]:
    if context.role not in {"ADMIN", "OPERATOR", "BUSINESS_ADMIN", "REMEDIATION_MANAGER"}:
        return []
    reviews = {str(row.get("id")): row for row in repo.list_payloads("review_items")}
    allowed_campaigns = {str(row.get("id")) for row in _visible_campaign_rows(repo, context)}
    result = []
    for action in repo.list_payloads("remediation_actions"):
        review = reviews.get(str(action.get("review_item_id")), {})
        provider = str(review.get("access_provider") or action.get("access_provider") or "")
        if context.role in {"ADMIN", "OPERATOR"}:
            if str(review.get("campaign_id")) not in allowed_campaigns:
                continue
        elif not _provider_allowed(context, provider):
            continue
        result.append(
            {
                "id": str(action.get("id")),
                "review_id": str(action.get("review_item_id")),
                "campaign_id": review.get("campaign_id"),
                "provider": provider,
                "identity_identifier": review.get("identity_identifier"),
                "access_name": review.get("access_name"),
                "action": action.get("action"),
                "status": str(action.get("status") or "pending"),
            }
        )
    return result


def search_authorized_remediations(
    repo: Repository, args: dict[str, Any], context: AuthorizationContext, hints: UIHints
) -> dict[str, Any]:
    text = str(args.get("text") or "").casefold()
    rows = [
        row
        for row in _remediation_rows(repo, context)
        if (not text or text in json.dumps(row, ensure_ascii=False).casefold())
        and (not args.get("status") or row["status"] == args["status"])
        and (not args.get("provider") or row["provider"] == args["provider"])
    ]
    limit = _limit(args)
    return {"items": rows[:limit], "count": len(rows), "truncated": len(rows) > limit}


def get_authorized_perimeter(
    repo: Repository, args: dict[str, Any], context: AuthorizationContext, hints: UIHints
) -> dict[str, Any]:
    if not _operational(context):
        return {"available": False, "item": None}
    kind = str(args.get("kind") or "")
    identifier = str(args.get("perimeter_id") or "")
    table = "organizations" if kind == "organization" else "information_systems"
    row = repo.get_payload(table, identifier)
    if row is None:
        return {"available": False, "item": None}
    return {
        "available": True,
        "item": {
            "id": identifier,
            "kind": kind,
            "name": row.get("name"),
            "active": bool(row.get("active", True)),
            "path": [item.get("name") for item in perimeter_path(repo, kind, identifier)],
        },
    }


def _authentication_rows(repo: Repository, context: AuthorizationContext) -> list[dict[str, Any]]:
    if not _operational(context):
        return []
    providers = sorted(
        {
            str(row.get("name"))
            for row in repo.list_payloads("providers")
            if _provider_allowed(context, row.get("name"))
        }
        | {
            str(row.get("provider"))
            for row in repo.list_payloads("identities")
            if _provider_allowed(context, row.get("provider"))
        }
    )
    return [{"provider": provider, **_provider_posture(repo, provider)} for provider in providers]


def get_authentication_posture_summary(
    repo: Repository, args: dict[str, Any], context: AuthorizationContext, hints: UIHints
) -> dict[str, Any]:
    rows = _authentication_rows(repo, context)
    identity_filters = any(
        args.get(key) is not None
        for key in ("identity_type", "organization", "information_system", "privileged_only")
    )
    if identity_filters:
        identities = _identity_rows(repo, context)
        if args.get("identity_type"):
            identities = [
                row for row in identities if row.get("identity_type") == args["identity_type"]
            ]
        if args.get("privileged_only") is True:
            identities = [row for row in identities if row.get("privileged_access")]
        for argument, perimeter_key in (
            ("organization", "organizations"),
            ("information_system", "information_systems"),
        ):
            if not args.get(argument):
                continue
            needle = str(args[argument]).casefold()
            identities = [
                row
                for row in identities
                if any(
                    needle
                    in {
                        str(item.get("id") or "").casefold(),
                        str(item.get("name") or "").casefold(),
                    }
                    for item in row.get("perimeters", {}).get(perimeter_key, [])
                )
            ]
        counts = Counter(str(row.get("provider")) for row in identities)
        rows = [
            {**row, "matching_identity_count": counts[row["provider"]]}
            for row in rows
            if counts[row["provider"]] > 0
        ]
    if args.get("provider"):
        rows = [row for row in rows if row["provider"] == args["provider"]]
    state_counts = Counter(str(row["state"]) for row in rows)
    return {
        "providers": rows[:MAX_RESULT_COUNT],
        "provider_count": len(rows),
        "by_state": dict(sorted(state_counts.items())),
        "note": "not_collected does not mean that an authentication control is disabled",
    }


_GROUP_FIELDS: dict[str, set[str]] = {
    "access": {"provider", "completeness", "capability"},
    "identity": {"provider", "identity_type", "status", "authentication_state"},
    "review": {"provider", "classification", "status"},
    "campaign": {"provider", "status"},
    "remediation": {"provider", "status"},
    "authentication_posture": {"provider", "authentication_state"},
    "golden": {"provider", "completeness", "capability"},
}


def _aggregate_rows(
    repo: Repository, context: AuthorizationContext, entity: str
) -> list[dict[str, Any]]:
    if entity == "access":
        return _access_rows(repo, context)
    if entity == "identity":
        return _identity_rows(repo, context)
    if entity == "review":
        return [
            {**row, "provider": row.get("access_provider")} for row in _review_rows(repo, context)
        ]
    if entity == "campaign":
        return [
            {
                **row,
                "providers": sorted(_campaign_providers(row, repo)),
                "provider": sorted(_campaign_providers(row, repo)),
            }
            for row in _visible_campaign_rows(repo, context)
        ]
    if entity == "remediation":
        return _remediation_rows(repo, context)
    if entity == "authentication_posture":
        return [
            {**row, "authentication_state": row.get("state")}
            for row in _authentication_rows(repo, context)
        ]
    if entity == "golden":
        return [
            {
                "id": f"{row.get('access_provider')}:{row.get('access_name')}",
                "provider": row.get("access_provider"),
                "completeness": row.get("completeness"),
                "capabilities": [
                    item.get("capability_id") for item in row.get("functional_rights", [])
                ],
            }
            for row in _visible_golden_rows(repo, context)
        ]
    return []


def aggregate_authorized_data(
    repo: Repository, args: dict[str, Any], context: AuthorizationContext, hints: UIHints
) -> dict[str, Any]:
    entity = str(args.get("entity"))
    metric = str(args.get("metric"))
    group_by = args.get("group_by")
    if group_by is not None and str(group_by) not in _GROUP_FIELDS.get(entity, set()):
        return {"available": False, "reason": "unsupported_combination"}
    rows = _aggregate_rows(repo, context, entity)
    raw_filters = args.get("filters")
    filters: dict[str, Any] = raw_filters if isinstance(raw_filters, dict) else {}
    for key, value in filters.items():
        if value is None:
            continue
        field = "capabilities" if key == "capability" else key
        rows = [
            row
            for row in rows
            if (
                value in row.get(field, [])
                if isinstance(row.get(field), list)
                else str(row.get(field) or "").casefold() == str(value).casefold()
            )
        ]
    if group_by is None:
        distinct_values = {str(row.get("id") or index) for index, row in enumerate(rows)}
        value = len(distinct_values) if metric == "distinct_count" else len(rows)
        return {"available": True, "entity": entity, "metric": metric, "value": value}
    counts: Counter[str] = Counter()
    distinct: dict[str, set[str]] = {}
    field = "capabilities" if group_by == "capability" else str(group_by)
    if group_by == "authentication_state":
        field = (
            "authentication_state"
            if entity == "authentication_posture"
            else "authentication_posture"
        )
    for row in rows:
        raw = row.get(field)
        if group_by == "authentication_state" and isinstance(raw, dict):
            raw = raw.get("state")
        group_values = raw if isinstance(raw, list) else [raw]
        for value in group_values:
            key = str(value or "unknown")
            if metric == "distinct_count":
                distinct.setdefault(key, set()).add(str(row.get("id") or id(row)))
            else:
                counts[key] += 1
    if metric == "distinct_count":
        counts.update({key: len(values) for key, values in distinct.items()})
    return {
        "available": True,
        "entity": entity,
        "metric": metric,
        "group_by": group_by,
        "groups": dict(sorted(counts.items())),
    }


_STRING = {"type": ["string", "null"], "maxLength": 200}
_LIMIT = {"type": "integer", "minimum": 1, "maximum": MAX_RESULT_COUNT}
_STRING_ARRAY = {
    "type": "array",
    "items": {"type": "string", "maxLength": 200},
    "maxItems": MAX_RESULT_COUNT,
    "uniqueItems": True,
}


def _schema(
    name: str, description: str, properties: dict[str, Any], required: list[str]
) -> dict[str, Any]:
    return {
        "type": "function",
        "name": name,
        "description": description,
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": False,
        },
    }


SEMANTIC_TOOL_FUNCTIONS = {
    "search_authorized_accesses": search_authorized_accesses,
    "get_authorized_access": get_authorized_access,
    "search_authorized_identities": search_authorized_identities,
    "get_authorized_identity": get_authorized_identity,
    "search_authorized_reviews": search_authorized_reviews,
    "get_authorized_review": get_authorized_review,
    "search_authorized_campaigns": search_authorized_campaigns,
    "get_authorized_campaign": get_authorized_campaign,
    "search_authorized_remediations": search_authorized_remediations,
    "get_authorized_perimeter": get_authorized_perimeter,
    "get_authentication_posture_summary": get_authentication_posture_summary,
    "aggregate_authorized_data": aggregate_authorized_data,
}

SEMANTIC_TOOL_SCHEMAS = [
    _schema(
        "search_authorized_accesses",
        "Search bounded Access DTOs after server-side EARE authorization",
        {
            "text": _STRING,
            "provider": _STRING,
            "organization_ids": _STRING_ARRAY,
            "information_system_ids": _STRING_ARRAY,
            "target": _STRING,
            "capability": _STRING,
            "permission": _STRING,
            "owner": _STRING,
            "owner_state": {
                "type": ["string", "null"],
                "enum": [None, "defined", "missing"],
            },
            "completeness": {
                "type": ["string", "null"],
                "enum": [None, "complete", "partial", "not_defined"],
            },
            "provenance": _STRING,
            "access_type": _STRING,
            "privileged": {"type": ["boolean", "null"]},
            "limit": _LIMIT,
        },
        [],
    ),
    _schema(
        "get_authorized_access",
        "Get one authorized Access DTO",
        {"access_id": {"type": "string", "minLength": 1, "maxLength": 200}},
        ["access_id"],
    ),
    _schema(
        "search_authorized_identities",
        "Search bounded Identity DTOs after server-side EARE authorization",
        {
            "text": _STRING,
            "provider": _STRING,
            "identity_type": _STRING,
            "status": _STRING,
            "owner": _STRING,
            "owner_state": {
                "type": ["string", "null"],
                "enum": [None, "defined", "missing"],
            },
            "access_id": _STRING,
            "access_name": _STRING,
            "organization_ids": _STRING_ARRAY,
            "information_system_ids": _STRING_ARRAY,
            "authentication_posture": {
                "type": ["string", "null"],
                "enum": [None, "collected", "not_collected", "unknown"],
            },
            "privileged_access": {"type": ["boolean", "null"]},
            "limit": _LIMIT,
        },
        [],
    ),
    _schema(
        "get_authorized_identity",
        "Get one authorized Identity DTO",
        {"identity_id": {"type": "string", "minLength": 1, "maxLength": 200}},
        ["identity_id"],
    ),
    _schema(
        "search_authorized_reviews",
        "Search authorized ReviewItem DTOs",
        {
            "text": _STRING,
            "provider": _STRING,
            "campaign_id": _STRING,
            "classification": _STRING,
            "status": _STRING,
            "limit": _LIMIT,
        },
        [],
    ),
    _schema(
        "get_authorized_review",
        "Get one authorized ReviewItem DTO; null resolves the authorized current review hint",
        {"review_id": {"type": ["string", "null"], "maxLength": 200}},
        ["review_id"],
    ),
    _schema(
        "search_authorized_campaigns",
        "Search authorized Campaign DTOs",
        {"text": _STRING, "provider": _STRING, "status": _STRING, "limit": _LIMIT},
        [],
    ),
    _schema(
        "get_authorized_campaign",
        "Get one authorized Campaign DTO",
        {"campaign_id": {"type": ["string", "null"], "maxLength": 200}},
        ["campaign_id"],
    ),
    _schema(
        "search_authorized_remediations",
        "Search authorized remediation DTOs",
        {"text": _STRING, "provider": _STRING, "status": _STRING, "limit": _LIMIT},
        [],
    ),
    _schema(
        "get_authorized_perimeter",
        "Get an EARE classification perimeter",
        {
            "kind": {"type": "string", "enum": ["organization", "information_system"]},
            "perimeter_id": {"type": "string", "minLength": 1, "maxLength": 200},
        },
        ["kind", "perimeter_id"],
    ),
    _schema(
        "get_authentication_posture_summary",
        "Summarize collected authentication posture without inferring absent controls",
        {
            "provider": _STRING,
            "identity_type": _STRING,
            "organization": _STRING,
            "information_system": _STRING,
            "privileged_only": {"type": ["boolean", "null"]},
        },
        [],
    ),
    _schema(
        "aggregate_authorized_data",
        "Calculate controlled counts over authorized EARE data without SQL",
        {
            "entity": {"type": "string", "enum": sorted(_GROUP_FIELDS)},
            "metric": {"type": "string", "enum": ["count", "distinct_count"]},
            "group_by": {
                "type": ["string", "null"],
                "enum": [
                    None,
                    "provider",
                    "completeness",
                    "capability",
                    "identity_type",
                    "classification",
                    "status",
                    "authentication_state",
                ],
            },
            "filters": {
                "type": "object",
                "properties": {
                    "provider": _STRING,
                    "completeness": _STRING,
                    "capability": _STRING,
                    "identity_type": _STRING,
                    "classification": _STRING,
                    "status": _STRING,
                    "authentication_state": _STRING,
                },
                "required": [],
                "additionalProperties": False,
            },
        },
        ["entity", "metric"],
    ),
]
