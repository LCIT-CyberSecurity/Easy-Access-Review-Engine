from __future__ import annotations

from dataclasses import asdict
from typing import Any

from access_review_engine.access_context import access_enrichment, source_business_context
from access_review_engine.domain import (
    Access,
    AccessAssignment,
    AccessRelation,
    AccessRelationType,
    ControlObject,
    ExpectedAccessModel,
    FunctionalModelCompleteness,
    FunctionalRight,
    GoldenAccessComment,
    Origin,
    OwnerRef,
    Provenance,
    Target,
    normalize_manual_target_node,
    target_path,
)
from access_review_engine.services import calculate_effective_accesses, functional_right_key
from access_review_engine.storage import Repository, hydrate_access


_TARGET_LEVELS = {"service", "component", "resource"}


def _context_value(context: dict[str, dict[str, Any]], field: str) -> dict[str, Any] | None:
    value = context.get(field)
    return dict(value) if isinstance(value, dict) and value.get("value") not in {None, ""} else None


def _context_projection(repo: Repository, access: Access) -> dict[str, Any]:
    """Project observed/manual context into reviewable Golden suggestions.

    This is deliberately a read-only projection. It never mutates an Access or
    creates an expected Golden definition.
    """
    source = source_business_context(asdict(access))
    enrichment = access_enrichment(repo, access.id) or {}
    manual = {
        field: {"value": enrichment[field], "provenance": "manual"}
        for field in ("application", "business_permission", "resource", "description", "owner")
        if enrichment.get(field) not in {None, ""}
    }
    fields: dict[str, dict[str, Any]] = {}
    for field in (*source.keys(), *manual.keys()):
        source_value = _context_value(source, field)
        manual_value = _context_value(manual, field)
        if source_value is None and manual_value is None:
            continue
        conflict = bool(
            source_value
            and manual_value
            and str(source_value["value"]).strip().casefold()
            != str(manual_value["value"]).strip().casefold()
        )
        fields[field] = {
            "source": source_value,
            "manual": manual_value,
            "conflict": conflict,
        }

    preferred = {
        field: values["source"] or values["manual"]
        for field, values in fields.items()
        if values["source"] or values["manual"]
    }
    target: dict[str, dict[str, Any]] = {}
    application = preferred.get("application")
    resource = preferred.get("resource")
    if application:
        target["service"] = {
            "identifier": str(application["value"]),
            "display_name": str(application["value"]),
            "type": "application",
            "provenance": application["provenance"],
        }
    if resource:
        target["resource"] = {
            "identifier": str(resource["value"]),
            "display_name": str(resource["value"]),
            "type": "business_object",
            "provenance": resource["provenance"],
        }

    owner = preferred.get("owner")
    owner_candidate = None
    if owner:
        owner_identity = str(owner["value"])
        known_identity = any(
            str(row.get("provider")) == access.provider
            and str(row.get("identifier")) == owner_identity
            for row in repo.list_payloads("identities")
        )
        owner_candidate = {
            "provider": access.provider,
            "identity": owner_identity,
            "provenance": owner["provenance"],
            "known_identity": known_identity,
        }

    permission = preferred.get("business_permission")
    mapped_capability_ids: list[str] = []
    mapping_provenance = None
    if permission:
        permission_value = str(permission["value"])
        mapping = next(
            (item for item in repo.list_permission_capability_mappings()
             if item.provider == access.provider
             and item.permission_identifier == permission_value),
            None,
        )
        if mapping is not None:
            mapped_capability_ids = list(mapping.capability_ids)
            mapping_provenance = mapping.provenance

    return {
        "source_context": source,
        "manual_context": manual,
        "fields": fields,
        "has_conflicts": any(value["conflict"] for value in fields.values()),
        "canonical_suggestions": {
            "target": target,
            "description": preferred.get("description"),
            "owner": owner_candidate,
            "business_permission": permission,
            "mapped_capability_ids": mapped_capability_ids,
            "mapping_provenance": mapping_provenance,
        },
    }


def functional_access_rows(repo: Repository, active: Any) -> list[dict[str, Any]]:
    """Build the Golden read model from immutable definitions and expected relations."""
    observed = {
        (str(row.get("provider")), str(row.get("name"))): row
        for row in repo.list_payloads("accesses")
    }
    definitions = {
        (item.provider, item.name): item for item in active.expected_access_definitions
    }
    assignments: dict[tuple[str, str], list[dict[str, str]]] = {}
    for assignment in active.assignments:
        key = (assignment.access_provider, assignment.access_name)
        assignments.setdefault(key, []).append(
            {
                "identity_provider": assignment.identity_provider,
                "identity_identifier": assignment.identity_identifier,
            }
        )
    models = {
        (item.access_provider, item.access_name): item
        for item in active.functional_access_models
    }
    comments = {
        (item.access_provider, item.access_name): item.comment
        for item in active.access_comments
    }
    keys = set(assignments) | set(definitions) | set(models)
    for relation in active.expected_access_relations:
        keys.add(relation.parent_key())
        keys.add(relation.child_key())

    observed_accesses: dict[tuple[str, str], Access] = {
        key: hydrate_access(row) for key, row in observed.items()
    }
    access_by_key: dict[tuple[str, str], Access] = dict(observed_accesses)
    access_by_key.update(definitions)
    display_names: dict[tuple[str, str], str] = {}
    for key, access in access_by_key.items():
        display_names[key] = access.display_name or access.name

    expected_rights = {key: list(model.rights) for key, model in models.items()}
    rows: list[dict[str, Any]] = []
    for key in sorted(keys, key=lambda value: (display_names.get(value, value[1]).casefold(), value)):
        access = access_by_key.get(key)
        if access is None:
            continue
        model = models.get(key)
        roots = {(key[0], key[1])}
        traversal = calculate_effective_accesses(
            [
                AccessAssignment(
                    provider=key[0],
                    access_name=key[1],
                    identity_provider="__golden_model__",
                    identity_identifier="__golden_model__",
                    origin=Origin("golden_model", True, False),
                )
            ],
            active.expected_access_relations,
            access_by_key.values(),
        )
        roots.update(
            (item.access_provider, item.access_name) for item in traversal.effective_accesses
        )
        rights_by_key: dict[tuple[Any, ...], dict[str, Any]] = {}
        for reachable in roots:
            for right in expected_rights.get(reachable, []):
                identity = functional_right_key(right)
                row = {
                    "target": asdict(right.target),
                    "target_path": target_path(right.target),
                    "capability_id": right.capability_id,
                    "provenance": right.provenance,
                    "native_permission": right.native_permission,
                    "granted_by": display_names.get(reachable, reachable[1]),
                }
                rights_by_key.setdefault(identity, row)
        observed_access = observed_accesses.get(key)
        context_access = observed_access or access
        context = _context_projection(repo, context_access)
        owner = context_access.access_owner
        native_permission = context_access.permission.identifier if context_access.permission else None
        rows.append(
            {
                "access_provider": key[0],
                "access_name": key[1],
                "access_display_name": display_names.get(key, key[1]),
                "access_type": access.control_object.type if access.control_object else None,
                "access_description": context_access.description,
                "access_target": asdict(context_access.target) if context_access.target else None,
                "access_permission": native_permission,
                "access_owner": owner.identity if owner else None,
                "owner_provider": owner.provider if owner else None,
                "source": key[0],
                "source_provenance": "observed" if key in observed else "manual",
                "completeness": (
                    model.completeness
                    if model
                    else FunctionalModelCompleteness.NOT_DEFINED
                ),
                "functional_rights": list(rights_by_key.values()),
                "effective_right_count": len(rights_by_key),
                "expected_identities": len(assignments.get(key, [])),
                "access_comment": comments.get(key),
                "relation_diagnostics": traversal.diagnostics,
                "observed_business_context": context["source_context"],
                "manual_business_context": context["manual_context"],
                "business_context_fields": context["fields"],
                "business_context_conflicts": context["has_conflicts"],
                "canonical_suggestions": context["canonical_suggestions"],
            }
        )
    return rows


def prepare_functional_model_update(
    repo: Repository, active: Any, payload: dict[str, Any]
) -> tuple[list[Access], list[AccessRelation], list[ExpectedAccessModel], list[GoldenAccessComment], str]:
    provider = _required_text(payload, "access_provider")
    name = _required_text(payload, "access_name")
    key = (provider, name)
    completeness = payload.get("completeness", FunctionalModelCompleteness.NOT_DEFINED)
    if completeness not in {item.value for item in FunctionalModelCompleteness}:
        raise ValueError("Completeness must be not_defined, partial, or complete")

    existing_definitions = {
        (item.provider, item.name): item for item in active.expected_access_definitions
    }
    observed_payload = repo.find_by_provider_name("accesses", provider, name)
    if observed_payload is not None:
        definition = hydrate_access(observed_payload)
    elif key in existing_definitions:
        definition = existing_definitions[key]
    elif payload.get("manual_access") is True:
        control_type = str(payload.get("access_type") or "access").strip()
        if not control_type:
            raise ValueError("Access type must be non-empty")
        definition = Access(
            name=name,
            provider=provider,
            display_name=str(payload.get("access_display_name") or name).strip(),
            description=str(payload.get("access_description") or "").strip() or None,
            control_object=ControlObject(type=control_type, identifier=name),
        )
    else:
        raise ValueError("Select a known Access or explicitly define an unobserved Access")

    owner_data = payload.get("access_owner")
    if owner_data is not None:
        if not isinstance(owner_data, dict):
            raise ValueError("Access owner must reference a known Identity")
        owner_provider = _required_text(owner_data, "provider")
        owner_identity = _required_text(owner_data, "identity")
        if not any(
            row.get("provider") == owner_provider and row.get("identifier") == owner_identity
            for row in repo.list_payloads("identities")
        ):
            raise ValueError("Access owner must reference a known Identity")
        definition.access_owner = OwnerRef(owner_provider, owner_identity)

    raw_rights = payload.get("rights", [])
    if not isinstance(raw_rights, list):
        raise ValueError("Functional rights must be a list")
    catalogue = {item.id: item for item in repo.list_capabilities()}
    rights: list[FunctionalRight] = []
    right_keys: set[tuple[Any, ...]] = set()
    for raw in raw_rights:
        if not isinstance(raw, dict):
            raise ValueError("Each functional right must be an object")
        cap_id = _required_text(raw, "capability_id")
        capability = catalogue.get(cap_id)
        if capability is None or not capability.active:
            raise ValueError("Choose an active Capability from the catalogue")
        target_data = raw.get("target")
        if not isinstance(target_data, dict) or set(target_data) - _TARGET_LEVELS:
            raise ValueError("Target may contain only service, component, and resource")
        normalized = {
            level: normalize_manual_target_node(target_data.get(level))
            for level in _TARGET_LEVELS
        }
        target = Target(**normalized)
        if not any(getattr(target, level) for level in _TARGET_LEVELS):
            raise ValueError("A functional right requires a Target")
        permission = raw.get("native_permission")
        if permission is not None and not isinstance(permission, str):
            raise ValueError("Native permission must be text")
        right = FunctionalRight(
            target=target,
            capability_id=cap_id,
            provenance=Provenance.MANUAL,
            native_permission=permission.strip() or None if permission else None,
        )
        identity = functional_right_key(right)
        if identity in right_keys:
            raise ValueError("Duplicate Target and Capability functional right")
        right_keys.add(identity)
        rights.append(right)

    models = {
        (item.access_provider, item.access_name): item
        for item in active.functional_access_models
    }
    models[key] = ExpectedAccessModel(provider, name, completeness, tuple(rights))

    definitions = existing_definitions | {key: definition}
    observed_accesses = {
        (str(row.get("provider")), str(row.get("name"))): hydrate_access(row)
        for row in repo.list_payloads("accesses")
    }
    observed_accesses.update(definitions)

    grants = payload.get("grants", [])
    if not isinstance(grants, list):
        raise ValueError("Granted Accesses must be a list")
    children: set[tuple[str, str]] = set()
    for grant in grants:
        if not isinstance(grant, dict):
            raise ValueError("Each granted Access must be an object")
        child = (_required_text(grant, "access_provider"), _required_text(grant, "access_name"))
        if child == key or child in children:
            raise ValueError("A GRANTS relation cannot target itself or be duplicated")
        if child not in observed_accesses:
            raise ValueError("GRANTS target must be a known or expected Access")
        children.add(child)
        if child not in definitions:
            definitions[child] = observed_accesses[child]

    relations = [
        relation for relation in active.expected_access_relations if relation.parent_key() != key
    ]
    current_by_child = {
        relation.child_key(): relation
        for relation in active.expected_access_relations
        if relation.parent_key() == key
    }
    for child_provider, child_name in sorted(children):
        relation = current_by_child.get((child_provider, child_name)) or AccessRelation(
            parent_provider=provider,
            parent_access_name=name,
            child_provider=child_provider,
            child_access_name=child_name,
            relation_type=AccessRelationType.GRANTS,
            origin=Origin("manual", True, False),
        )
        relations.append(relation)

    comments = {
        (item.access_provider, item.access_name): item for item in active.access_comments
    }
    access_comment = payload.get("access_comment", "")
    if not isinstance(access_comment, str) or len(access_comment) > 4000:
        raise ValueError("Access comment must be text of at most 4000 characters")
    if access_comment.strip():
        comments[key] = GoldenAccessComment(provider, name, access_comment.strip())
    else:
        comments.pop(key, None)

    version_comment = payload.get("version_comment", "")
    if not isinstance(version_comment, str) or len(version_comment) > 4000:
        raise ValueError("Version comment must be text of at most 4000 characters")
    return (
        sorted(definitions.values(), key=lambda item: (item.provider, item.name)),
        sorted(relations, key=lambda item: item.key()),
        sorted(models.values(), key=lambda item: (item.access_provider, item.access_name)),
        sorted(comments.values(), key=lambda item: (item.access_provider, item.access_name)),
        version_comment.strip() or f"Updated functional model for {name}",
    )


def _required_text(value: dict[str, Any], field: str) -> str:
    raw = value.get(field)
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(f"{field.replace('_', ' ').capitalize()} is required")
    return raw.strip()
