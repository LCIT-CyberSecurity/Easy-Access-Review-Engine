"""Simple, validated business-field mapping for directory-backed Access objects."""
from __future__ import annotations

import re
from typing import Any, Mapping

from access_review_engine.domain import Access


BUSINESS_CONTEXT_METADATA_KEY = "eare_business_context"
BUSINESS_FIELDS = (
    "display_name",
    "description",
    "application",
    "business_permission",
    "resource",
    "owner",
)
MAPPING_MODES = {"default", "attribute", "static", "none"}

_ATTRIBUTE_NAME = re.compile(r"^(?:[A-Za-z][A-Za-z0-9-]{0,63}|[0-9]+(?:\.[0-9]+)+)$")
_SENSITIVE_ATTRIBUTES = {
    "unicodepwd",
    "supplementalcredentials",
    "userpassword",
    "authpassword",
    "ntpwdhistory",
    "dbcspwd",
    "lmowfpwd",
    "passwordhash",
    "accesstoken",
    "refreshtoken",
    "clientsecret",
    "apikey",
    "privatekey",
    "credentials",
}
_SENSITIVE_ATTRIBUTE_PARTS = (
    "password",
    "token",
    "secret",
    "privatekey",
    "credential",
)
_TECHNICAL_ATTRIBUTES = {
    "sid",
    "objectsid",
    "objectguid",
    "primarygroupid",
    "distinguishedname",
    "dn",
    "entryuuid",
    "member",
    "uniquemember",
    "memberuid",
    "samaccountname",
    "userprincipalname",
    "uid",
    "entrydn",
}

_DEFAULT_ATTRIBUTES: dict[str, dict[str, tuple[str, ...]]] = {
    "active_directory": {
        "display_name": ("Name", "SamAccountName"),
        "description": ("Description",),
        "application": (),
        "business_permission": (),
        "resource": (),
        "owner": ("managedBy",),
    },
    "openldap": {
        "display_name": ("cn",),
        "description": ("description",),
        "application": (),
        "business_permission": (),
        "resource": (),
        "owner": ("owner",),
    },
}


class SourceMappingError(ValueError):
    """A source mapping is invalid or attempts to expose a protected attribute."""


def canonical_attribute_name(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).casefold())


def validate_attribute_name(kind: str, value: object) -> str:
    """Return one safe connector attribute name, treating it strictly as data."""
    if not isinstance(value, str) or not _ATTRIBUTE_NAME.fullmatch(value):
        raise SourceMappingError("Source attribute names may contain only letters, digits and hyphens")
    canonical = canonical_attribute_name(value)
    if canonical in _SENSITIVE_ATTRIBUTES or any(part in canonical for part in _SENSITIVE_ATTRIBUTE_PARTS):
        raise SourceMappingError(f"Sensitive source attribute is not allowed: {value}")
    if canonical in _TECHNICAL_ATTRIBUTES:
        raise SourceMappingError(f"Technical reconciliation attribute cannot be mapped: {value}")
    if kind not in _DEFAULT_ATTRIBUTES:
        raise SourceMappingError(f"Unsupported connector type: {kind}")
    return value


def is_safe_attribute(kind: str, value: object) -> bool:
    try:
        validate_attribute_name(kind, value)
    except SourceMappingError:
        return False
    return True


def default_business_mapping(kind: str) -> dict[str, dict[str, str]]:
    if kind not in _DEFAULT_ATTRIBUTES:
        raise SourceMappingError(f"Unsupported connector type: {kind}")
    return {field: {"mode": "default"} for field in BUSINESS_FIELDS}


def validate_business_mapping(kind: str, value: object) -> dict[str, dict[str, str]]:
    """Validate the deliberately small mapping language and return normalized entries."""
    if value is None:
        return default_business_mapping(kind)
    if not isinstance(value, dict):
        raise SourceMappingError("business_mapping must be a mapping")
    unknown = set(value) - set(BUSINESS_FIELDS)
    if unknown:
        raise SourceMappingError("Unsupported business mapping fields: " + ", ".join(sorted(unknown)))
    normalized = default_business_mapping(kind)
    for field, raw in value.items():
        if not isinstance(raw, dict):
            raise SourceMappingError(f"business_mapping.{field} must be a mapping")
        mode = str(raw.get("mode", "default")).strip().lower()
        if mode not in MAPPING_MODES:
            raise SourceMappingError(f"Unsupported mapping mode for {field}: {mode}")
        entry = {"mode": mode}
        if mode == "attribute":
            entry["attribute"] = validate_attribute_name(kind, raw.get("attribute"))
        elif mode == "static":
            static_value = raw.get("value")
            if not isinstance(static_value, str) or not static_value.strip():
                raise SourceMappingError(f"Static mapping for {field} requires a value")
            if len(static_value) > 500:
                raise SourceMappingError(f"Static mapping for {field} is too long")
            entry["value"] = static_value.strip()
        normalized[field] = entry
    return normalized


def connector_business_mapping(config: Mapping[str, Any] | None, kind: str) -> dict[str, dict[str, str]]:
    raw = config.get("business_mapping") if config else None
    return validate_business_mapping(kind, raw)


def required_mapping_attributes(config: Mapping[str, Any] | None, kind: str) -> tuple[str, ...]:
    mapping = connector_business_mapping(config, kind)
    attributes = {
        entry["attribute"]
        for entry in mapping.values()
        if entry.get("mode") == "attribute" and entry.get("attribute")
    }
    return tuple(sorted(attributes, key=str.casefold))


def default_attribute_candidates(kind: str) -> tuple[str, ...]:
    values = {attribute for choices in _DEFAULT_ATTRIBUTES[kind].values() for attribute in choices}
    if kind == "active_directory":
        values.update({"info", *(f"extensionAttribute{index}" for index in range(1, 16))})
    return tuple(sorted(values, key=str.casefold))


def build_business_context(
    kind: str,
    attributes: Mapping[str, object],
    config: Mapping[str, Any] | None = None,
) -> dict[str, dict[str, str]]:
    """Resolve source fields once for preview and synchronization."""
    mapping = connector_business_mapping(config, kind)
    available = {str(key).casefold(): (str(key), value) for key, value in attributes.items()}
    context: dict[str, dict[str, str]] = {}
    for field in BUSINESS_FIELDS:
        entry = mapping[field]
        mode = entry["mode"]
        if mode == "none":
            continue
        if mode == "static":
            context[field] = {
                "value": entry["value"],
                "provenance": "static",
            }
            continue
        candidates = (
            (entry["attribute"],)
            if mode == "attribute"
            else _DEFAULT_ATTRIBUTES[kind][field]
        )
        for attribute in candidates:
            found = available.get(attribute.casefold())
            if found is None:
                continue
            actual_name, raw_value = found
            value = _first_text(raw_value)
            if value is None:
                continue
            context[field] = {
                "value": value,
                "provenance": "source_attribute" if mode == "attribute" else "native",
                "attribute": actual_name,
            }
            break
    return context


def apply_business_context(access: Access, context: Mapping[str, Mapping[str, str]]) -> Access:
    """Attach source context without changing the technical entitlement identity."""
    display_name = context.get("display_name", {}).get("value")
    description = context.get("description", {}).get("value")
    display_provenance = context.get("display_name", {}).get("provenance")
    if display_name and (display_provenance != "native" or not access.display_name):
        access.display_name = display_name
        if access.control_object is not None:
            access.control_object.display_name = display_name
    if description:
        access.description = description
        if access.control_object is not None:
            access.control_object.description = description
    access.metadata[BUSINESS_CONTEXT_METADATA_KEY] = {
        field: dict(context[field]) for field in BUSINESS_FIELDS if field in context
    }
    return access


def map_access_business_context(
    access: Access,
    kind: str,
    attributes: Mapping[str, object],
    config: Mapping[str, Any] | None = None,
) -> Access:
    return apply_business_context(access, build_business_context(kind, attributes, config))


def mapping_diagnostics(
    kind: str,
    config: Mapping[str, Any] | None,
    discovered: Mapping[str, Mapping[str, object]],
) -> list[dict[str, object]]:
    """Describe mapping coverage independently from connection health."""
    mapping = connector_business_mapping(config, kind)
    by_name = {name.casefold(): (name, details) for name, details in discovered.items()}
    rows: list[dict[str, object]] = []
    for field in BUSINESS_FIELDS:
        entry = mapping[field]
        mode = entry["mode"]
        if mode == "none" or (mode == "default" and not _DEFAULT_ATTRIBUTES[kind][field]):
            rows.append({"field": field, "mode": mode, "status": "not_configured"})
            continue
        if mode == "static":
            rows.append({"field": field, "mode": mode, "status": "configured"})
            continue
        candidates = (
            (entry["attribute"],)
            if mode == "attribute"
            else _DEFAULT_ATTRIBUTES[kind][field]
        )
        selected = next((by_name[item.casefold()] for item in candidates if item.casefold() in by_name), None)
        if selected is None:
            rows.append({
                "field": field,
                "mode": mode,
                "attribute": candidates[0] if candidates else None,
                "status": "not_found",
                "coverage": 0,
            })
            continue
        name, details = selected
        coverage = int(details.get("coverage", 0))
        rows.append({
            "field": field,
            "mode": mode,
            "attribute": name,
            "status": "ok" if coverage else "warning",
            "coverage": coverage,
            "samples": list(details.get("samples", []))[:3],
        })
    return rows


def _first_text(value: object) -> str | None:
    if isinstance(value, (list, tuple)):
        for item in value:
            resolved = _first_text(item)
            if resolved is not None:
                return resolved
        return None
    if value is None:
        return None
    text = str(value).strip()
    return text or None
