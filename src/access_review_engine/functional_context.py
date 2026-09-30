"""Human-readable, bounded projection of observed Keycloak authorization evidence."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from typing import Any

from access_review_engine.domain import Access, AccessRelation, Capability, ExpectedAccessModel


def _label(node: dict[str, Any] | None) -> str:
    if not isinstance(node, dict):
        return ""
    value = str(node.get("display_name") or "")
    if value and not value.startswith("${"):
        return value
    return str(node.get("client_id") or node.get("identifier") or "")


def application_for_access(access: Access) -> str:
    if not access.target:
        return ""
    component = access.target.component or {}
    service = access.target.service or {}
    if str(service.get("identifier", "")).casefold() == "keycloak":
        if access.control_object and access.control_object.type == "keycloak_client_role":
            metadata = access.control_object.metadata or {}
            return _label(
                {
                    "display_name": metadata.get("client_display_name"),
                    "client_id": metadata.get("client_id"),
                }
            )
        realm = str(service.get("realm") or _label(component))
        return f"Keycloak realm {realm}" if realm else "Keycloak"
    return _label(service)


def system_access(access: Access) -> bool:
    control = access.control_object
    if control is None:
        return False
    label = (access.display_name or access.name).casefold()
    if control.type == "keycloak_realm_role":
        return label in {"offline_access", "uma_authorization"} or label.startswith(
            "default-roles-"
        )
    if control.type == "keycloak_client_role":
        return str(control.metadata.get("client_id") or "").casefold() in {
            "account",
            "realm-management",
        }
    return False


def functional_context(
    access: Access,
    accesses: Iterable[Access],
    relations: Iterable[AccessRelation],
    models: Iterable[ExpectedAccessModel],
    *,
    max_depth: int = 8,
    capabilities: Iterable[Capability] | None = None,
) -> dict[str, Any]:
    """Resolve bounded downstream grants without inferring rights from role names."""
    by_key = {(item.provider, item.name): item for item in accesses}
    by_model = {(item.access_provider, item.access_name): item for item in models}
    capability_labels = {item.id: item.label for item in (capabilities or ())}
    adjacency: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for relation in relations:
        if relation.relation_type == "grants":
            adjacency.setdefault(relation.parent_key(), []).append(relation.child_key())
    root = (access.provider, access.name)
    queue = deque([(root, 0, (root,))])
    seen = {root}
    grants: list[dict[str, Any]] = []
    rights: dict[tuple[str, str, str], dict[str, Any]] = {}
    applications: set[str] = set()
    completeness = "not_defined"
    model_seen = False
    while queue:
        key, depth, path = queue.popleft()
        current = by_key.get(key)
        app = ""
        if current is not None:
            app = application_for_access(current)
            if app and (
                key == root
                and current.control_object
                and current.control_object.type != "keycloak_group"
                or key != root
            ):
                applications.add(app)
            if key != root:
                grants.append(
                    {
                        "access_provider": key[0],
                        "access_name": key[1],
                        "display_name": current.display_name or current.name,
                        "application": app,
                        "path": [
                            by_key[item].display_name or by_key[item].name
                            for item in path
                            if item in by_key
                        ],
                    }
                )
        model = by_model.get(key)
        if model:
            model_seen = True
            if model.completeness == "partial":
                completeness = "partial"
            elif model.completeness == "complete" and completeness == "not_defined":
                completeness = "complete"
            for right in model.rights:
                target = right.target
                resource = _label(target.resource)
                component = _label(target.component)
                application = app or component
                if application:
                    applications.add(application)
                identity = (application, resource, right.capability_id)
                rights.setdefault(
                    identity,
                    {
                        "application": application,
                        "resource": resource,
                        "resource_id": str((target.resource or {}).get("identifier") or ""),
                        "capability": right.capability_id,
                        "capability_label": capability_labels.get(
                            right.capability_id, right.capability_id
                        ),
                        "granted_by": current.display_name or current.name if current else key[1],
                        "provenance": right.provenance,
                        "native_permission": right.native_permission,
                        "source_evidence": (target.resource or {}).get("metadata", {}).get(
                            "keycloak_authorization"
                        ),
                    },
                )
        if depth < max_depth:
            for child in adjacency.get(key, []):
                if child not in seen:
                    seen.add(child)
                    queue.append((child, depth + 1, (*path, child)))
    business_apps = {name for name in applications if not name.startswith("Keycloak realm ")}
    explanation = ""
    if completeness == "not_defined":
        explanation = (
            "Authorization rights depend on dynamic or conditional policies and cannot be "
            "fully determined from the collected configuration."
            if model_seen
            else "Functional permissions are not exposed by the source."
        )
    return {
        "application": ", ".join(sorted(business_apps or applications)),
        "functional_rights": list(rights.values()),
        "functional_completeness": completeness,
        "functional_explanation": explanation,
        "grants": grants,
        "system_access": system_access(access),
        "access_type": access.control_object.type if access.control_object else "access",
        "technical_entitlement": access.permission.identifier if access.permission else "",
    }
