from __future__ import annotations

from dataclasses import asdict

import pytest

from access_review_engine.access_context import (
    access_context_for_payload,
    access_enrichment,
    save_access_enrichment,
    split_multi_value,
)
from access_review_engine.domain import (
    Access,
    ControlObject,
    GoldenSourceAssignment,
    Permission,
)
from access_review_engine.golden_annotations import (
    annotation_for_assignment,
    copy_assignment_annotations,
    normalize_assignment_comment,
    set_assignment_annotation,
)
from access_review_engine.services import create_golden_source, create_golden_version
from access_review_engine.source_mapping import BUSINESS_CONTEXT_METADATA_KEY
from access_review_engine.storage import Repository


def _access(name: str = "GG_SAGE_RW:member", native_id: str = "SID-G1", object_id: str = "access-1") -> Access:
    return Access(
        name,
        "corp-ad",
        ControlObject("group", name.split(":", 1)[0], native_id=native_id),
        Permission("member"),
        metadata={
            BUSINESS_CONTEXT_METADATA_KEY: {
                "application": {
                    "value": "Sage",
                    "provenance": "source_attribute",
                    "attribute": "extensionAttribute5",
                },
                "business_permission": {
                    "value": "ReadOnly",
                    "provenance": "source_attribute",
                    "attribute": "extensionAttribute6",
                },
            }
        },
        id=object_id,
    )


def test_manual_enrichment_is_keyed_by_access_id_and_survives_rename(tmp_path) -> None:
    with Repository(tmp_path / "context.db") as repo:
        access = _access()
        repo.upsert("accesses", access)
        saved = save_access_enrichment(
            repo,
            access.id,
            {"application": "Sage", "business_permission": "ReadWrite", "resource": "Invoices"},
            "admin",
        )
        assert saved and saved["access_id"] == access.id

        renamed = _access("GG_SAGE_FINANCE_RW:member", object_id=access.id)
        repo.upsert("accesses", renamed)
        assert access_enrichment(repo, access.id)["resource"] == "Invoices"

        view = access_context_for_payload(repo, asdict(renamed))
        assert view["fields"]["application"]["conflict"] is False
        assert view["fields"]["business_permission"]["conflict"] is True
        assert view["fields"]["business_permission"]["source"]["value"] == "ReadOnly"
        assert view["fields"]["business_permission"]["manual"]["value"] == "ReadWrite"


def test_manual_field_removal_does_not_mutate_source_context(tmp_path) -> None:
    with Repository(tmp_path / "context.db") as repo:
        access = _access()
        repo.upsert("accesses", access)
        save_access_enrichment(repo, access.id, {"application": "Sage", "resource": "Invoices"}, "admin")
        updated = save_access_enrichment(repo, access.id, {"resource": ""}, "admin")
        assert updated and "resource" not in updated
        assert updated["application"] == "Sage"
        stored_access = repo.get_payload("accesses", access.id)
        assert stored_access["metadata"][BUSINESS_CONTEXT_METADATA_KEY]["application"]["value"] == "Sage"


def test_reused_name_with_new_internal_id_does_not_inherit_manual_information(tmp_path) -> None:
    with Repository(tmp_path / "context.db") as repo:
        old = _access(object_id="old-access")
        repo.upsert("accesses", old)
        save_access_enrichment(repo, old.id, {"application": "Sage"}, "admin")
        repo.delete_ids("accesses", {old.id})

        replacement = _access(native_id="SID-G2", object_id="new-access")
        repo.upsert("accesses", replacement)
        assert access_enrichment(repo, replacement.id) is None
        assert access_enrichment(repo, old.id)["application"] == "Sage"


def test_golden_assignment_comments_are_versioned_and_follow_stable_rename(tmp_path) -> None:
    source = create_golden_source("main")
    old_assignment = GoldenSourceAssignment(
        "corp-ad",
        "GG_SAGE_RW:member",
        "corp-ad",
        "alice.old",
        access_native_id="SID-G1",
        access_permission="member",
        identity_native_id="SID-U1",
    )
    renamed_assignment = GoldenSourceAssignment(
        "corp-ad",
        "GG_SAGE_FINANCE_RW:member",
        "corp-ad",
        "alice.new",
        access_native_id="SID-G1",
        access_permission="member",
        identity_native_id="SID-U1",
    )
    v1 = create_golden_version(source, [old_assignment], "test", comment="Initial model")
    v2 = create_golden_version(source, [renamed_assignment], "test", [v1], parent_version_id=v1.id)

    with Repository(tmp_path / "golden.db") as repo:
        set_assignment_annotation(repo, v1, old_assignment, "Backup for Finance Manager", "admin")
        copy_assignment_annotations(repo, v1, v2)

        assert annotation_for_assignment(repo, v1.id, old_assignment)["comment"] == "Backup for Finance Manager"
        assert annotation_for_assignment(repo, v2.id, renamed_assignment)["comment"] == "Backup for Finance Manager"
        set_assignment_annotation(repo, v2, renamed_assignment, "Updated rationale", "admin")
        assert annotation_for_assignment(repo, v1.id, old_assignment)["comment"] == "Backup for Finance Manager"
        assert annotation_for_assignment(repo, v2.id, renamed_assignment)["comment"] == "Updated rationale"


def test_removed_assignment_comment_remains_historical_only(tmp_path) -> None:
    source = create_golden_source("main")
    assignment = GoldenSourceAssignment("corp-ad", "group:member", "corp-ad", "alice")
    v1 = create_golden_version(source, [assignment], "test")
    v2 = create_golden_version(source, [], "test", [v1], parent_version_id=v1.id)
    with Repository(tmp_path / "golden.db") as repo:
        set_assignment_annotation(repo, v1, assignment, "Historical reason", "admin")
        copy_assignment_annotations(repo, v1, v2)
        assert annotation_for_assignment(repo, v1.id, assignment)["comment"] == "Historical reason"
        assert repo.list_payloads("golden_assignment_annotations") == [annotation_for_assignment(repo, v1.id, assignment)]


def test_golden_comment_input_is_normalized_and_bounded_before_persistence() -> None:
    assert normalize_assignment_comment("  rationale  ") == "rationale"
    assert normalize_assignment_comment("   ") is None
    with pytest.raises(ValueError):
        normalize_assignment_comment({"comment": "not text"})
    with pytest.raises(ValueError):
        normalize_assignment_comment("x" * 4001)


def test_split_multi_value_reads_each_application_once():
    assert split_multi_value("CRM, ERP;Payroll | CRM") == ["CRM", "ERP", "Payroll"]
    assert split_multi_value("  ") == []
    assert split_multi_value(None) == []
