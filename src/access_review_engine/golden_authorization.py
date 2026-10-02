"""Shared Golden read authorization for API and chatbot projections."""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


def golden_required_providers(versions: Iterable[Any]) -> set[str]:
    """Resolve all provider domains exposed by the supplied Golden versions."""
    providers: set[str] = set()
    for version in versions:
        assignments = (
            version.get("assignments", [])
            if isinstance(version, Mapping)
            else getattr(version, "assignments", [])
        )
        for assignment in assignments:
            for field in ("access_provider", "identity_provider"):
                value = (
                    assignment.get(field)
                    if isinstance(assignment, Mapping)
                    else getattr(assignment, field, None)
                )
                if isinstance(value, str) and value.strip():
                    providers.add(value.strip())
        for collection_name, fields in (
            ("expected_access_definitions", ("provider",)),
            ("expected_access_relations", ("parent_provider", "child_provider")),
            ("functional_access_models", ("access_provider",)),
            ("access_comments", ("access_provider",)),
        ):
            collection = (
                version.get(collection_name, [])
                if isinstance(version, Mapping)
                else getattr(version, collection_name, [])
            )
            for item in collection:
                for field in fields:
                    value = (
                        item.get(field)
                        if isinstance(item, Mapping)
                        else getattr(item, field, None)
                    )
                    if isinstance(value, str) and value.strip():
                        providers.add(value.strip())
    return providers


def can_access_golden(role: str, scopes: Iterable[str], versions: Iterable[Any]) -> bool:
    """Apply the Golden role contract; operators fail closed without resolved domains."""
    if role == "ADMIN":
        return True
    if role != "OPERATOR":
        return False
    required = golden_required_providers(versions)
    if not required:
        return False
    allowed = {str(scope).strip() for scope in scopes if str(scope).strip()}
    return "*" in allowed or required <= allowed
