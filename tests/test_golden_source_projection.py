from __future__ import annotations

from pathlib import Path

from access_review_engine.domain import Access, ControlObject, PermissionCapabilityMapping
from access_review_engine.golden_functional import _context_projection
from access_review_engine.storage import Repository


def test_source_mapping_becomes_reviewable_golden_suggestion_only(tmp_path: Path) -> None:
    db = tmp_path / "projection.db"
    access = Access(
        name="GG-Finance:member",
        provider="AD-CORP",
        control_object=ControlObject("group", "GG-Finance"),
        metadata={
            "eare_business_context": {
                "application": {
                    "value": "Sage",
                    "provenance": "source_attribute",
                    "mapping_mode": "configured",
                    "attribute": "extensionAttribute5",
                },
                "business_permission": {
                    "value": "ReadWrite",
                    "provenance": "source_attribute",
                    "mapping_mode": "configured",
                    "attribute": "extensionAttribute6",
                },
                "resource": {
                    "value": "Invoices",
                    "provenance": "source_attribute",
                    "mapping_mode": "configured",
                    "attribute": "extensionAttribute7",
                },
            }
        },
    )
    with Repository(db) as repo:
        repo.upsert("accesses", access)
        repo.save_permission_capability_mapping(
            PermissionCapabilityMapping("AD-CORP", "ReadWrite", ("read", "write"))
        )
        projection = _context_projection(repo, access)

    assert projection["canonical_suggestions"]["target"]["service"]["identifier"] == "Sage"
    assert projection["canonical_suggestions"]["target"]["resource"]["identifier"] == "Invoices"
    assert projection["canonical_suggestions"]["mapped_capability_ids"] == ["read", "write"]
    assert projection["canonical_suggestions"]["mapping_provenance"] == "mapped"
    assert projection["source_context"]["application"]["attribute"] == "extensionAttribute5"
    assert projection["has_conflicts"] is False
