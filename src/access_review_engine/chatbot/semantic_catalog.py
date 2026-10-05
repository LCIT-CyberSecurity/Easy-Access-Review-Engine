"""Provider-neutral logical vocabulary exposed to the EARE Chatbot."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SemanticEntity:
    name: str
    definition: str


SEMANTIC_CATALOG: tuple[SemanticEntity, ...] = (
    SemanticEntity("Identity", "A person, technical account, shared account, or group."),
    SemanticEntity("Access", "A reviewable entitlement, role, or right."),
    SemanticEntity("AccessAssignment", "An observed relationship from one Identity to one Access."),
    SemanticEntity("AccessRelation", "A grant or inheritance relationship between Access objects."),
    SemanticEntity("Permission", "A native technical permission supplied by a source."),
    SemanticEntity("Target", "An application, service, component, or resource."),
    SemanticEntity("Capability", "A normalized functional action; the catalog is extensible."),
    SemanticEntity(
        "FunctionalRight", "A functional representation combining Target and Capability."
    ),
    SemanticEntity("Snapshot", "An immutable observed state collected from source systems."),
    SemanticEntity("GoldenSource", "The versioned expected reference state."),
    SemanticEntity("GoldenSourceVersion", "An immutable version of a Golden Source."),
    SemanticEntity("Campaign", "An access-review process based on a snapshot and reference scope."),
    SemanticEntity("ReviewItem", "An AccessAssignment submitted to human review."),
    SemanticEntity("Decision", "A human approve or revoke decision on a ReviewItem."),
    SemanticEntity("RemediationAction", "Follow-up work derived from a human review decision."),
    SemanticEntity(
        "Organization",
        "A classification and targeting perimeter; it is not a permission or authorization rule.",
    ),
    SemanticEntity(
        "InformationSystem",
        "A classification and targeting perimeter; it is not a permission or authorization rule.",
    ),
)

BUILT_IN_CAPABILITY_IDS = ("read", "write", "delete", "execute", "approve", "grant", "admin")


def prompt_catalog() -> str:
    definitions = "\n".join(f"- {item.name}: {item.definition}" for item in SEMANTIC_CATALOG)
    capabilities = ", ".join(BUILT_IN_CAPABILITY_IDS)
    return (
        f"{definitions}\n"
        "Built-in Capability identifiers currently include "
        f"{capabilities}; this list is extensible."
    )
