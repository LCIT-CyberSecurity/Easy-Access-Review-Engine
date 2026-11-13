"""Campaign review-scope validation and provider-domain authorization."""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


class CampaignScopeError(ValueError):
    """The requested review scope is malformed or empty."""


def normalize_campaign_scope(value: object) -> dict[str, Any]:
    """Validate campaign selection syntax without conflating it with user scopes."""
    if value is None:
        return {"type": "all"}
    if not isinstance(value, Mapping):
        raise CampaignScopeError("Campaign scope must be an object")
    scope_type = value.get("type", "all")
    perimeter_value = value.get("perimeters", {})
    if perimeter_value is None:
        perimeter_value = {}
    if not isinstance(perimeter_value, Mapping):
        raise CampaignScopeError("Campaign perimeter scope must be an object")
    perimeters: dict[str, Any] = {}
    for field in ("organizations", "information_systems"):
        values = perimeter_value.get(field, [])
        if not isinstance(values, list) or any(not isinstance(item, str) or not item.strip() for item in values):
            raise CampaignScopeError(f"Campaign perimeter {field} must be a list of IDs")
        perimeters[field] = list(dict.fromkeys(item.strip() for item in values))
    for field in ("include_organization_descendants", "include_information_system_descendants"):
        if field in perimeter_value and not isinstance(perimeter_value[field], bool):
            raise CampaignScopeError(f"Campaign perimeter flag {field} must be boolean")
        perimeters[field] = bool(perimeter_value.get(field, False))
    perimeter_scope = {"perimeters": perimeters} if any(perimeters[field] for field in ("organizations", "information_systems")) else {}
    if scope_type == "all":
        return {"type": "all", **perimeter_scope}
    if scope_type == "providers":
        raw_values = value.get("values")
        if not isinstance(raw_values, list):
            raise CampaignScopeError("Provider scope values must be a list")
        providers: list[str] = []
        for raw in raw_values:
            if not isinstance(raw, str) or not raw.strip():
                raise CampaignScopeError("Each provider scope value must be non-empty text")
            provider = raw.strip()
            if provider not in providers:
                providers.append(provider)
        if not providers:
            raise CampaignScopeError("Select at least one provider for this campaign scope")
        return {"type": "providers", "values": providers, **perimeter_scope}
    if scope_type == "accesses":
        raw_values = value.get("values")
        if not isinstance(raw_values, list) or not raw_values:
            raise CampaignScopeError("Select at least one Access for this campaign scope")
        accesses: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for raw in raw_values:
            if not isinstance(raw, Mapping):
                raise CampaignScopeError("Each Access scope value must include provider and name")
            provider, name = raw.get("provider"), raw.get("name")
            if (
                not isinstance(provider, str)
                or not provider.strip()
                or not isinstance(name, str)
                or not name.strip()
            ):
                raise CampaignScopeError("Each Access scope value must include provider and name")
            key = (provider.strip(), name.strip())
            if key in seen:
                raise CampaignScopeError("Access scope contains a duplicate reference")
            seen.add(key)
            accesses.append({"provider": key[0], "name": key[1]})
        return {"type": "accesses", "values": accesses, **perimeter_scope}
    raise CampaignScopeError("Campaign scope must be all, providers, or accesses")


def campaign_authorization_providers(
    scope: Mapping[str, Any] | None,
    comparison_states: Iterable[Mapping[str, Any]],
) -> set[str]:
    """Backward-compatible name for the shared campaign-domain resolver."""
    return campaign_required_providers(scope, comparison_states)

def campaign_required_providers(
    scope: Mapping[str, Any] | None,
    comparison_states: Iterable[Mapping[str, Any]] = (),
    *,
    snapshot_providers: Iterable[str] = (),
    review_items: Iterable[Mapping[str, Any]] = (),
) -> set[str]:
    """Resolve required domains from draft evidence or persisted historical reviews.

    Materialized ReviewItems take priority for historical campaigns because their two
    provider fields describe the evidence that the campaign actually exposes.
    """
    normalized = normalize_campaign_scope(scope)
    providers: set[str] = set()
    if normalized["type"] == "providers":
        providers.update(normalized["values"])
    elif normalized["type"] == "accesses":
        providers.update(item["provider"] for item in normalized["values"])

    persisted = list(review_items)
    evidence = persisted if persisted else comparison_states
    for row in evidence:
        for field in ("access_provider", "identity_provider"):
            provider = row.get(field)
            if isinstance(provider, str) and provider.strip():
                providers.add(provider.strip())

    if normalized["type"] == "all":
        providers.update(
            provider.strip()
            for provider in snapshot_providers
            if isinstance(provider, str) and provider.strip()
        )
    return providers


def can_access_campaign(role: str, scopes: Iterable[str], providers: Iterable[str]) -> bool:
    """Allow ADMIN globally and OPERATOR only when every exposed provider is authorized."""
    if role == "ADMIN":
        return True
    if role != "OPERATOR":
        return False
    required = set(providers)
    if not required:
        return False
    allowed = {str(scope).strip() for scope in scopes if str(scope).strip()}
    if "*" in allowed:
        return True
    return required <= allowed
