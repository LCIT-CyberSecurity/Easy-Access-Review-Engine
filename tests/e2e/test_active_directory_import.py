from __future__ import annotations

from pathlib import Path

from access_review_engine.domain import AccessAssignment, Origin
from access_review_engine.importers.ad import import_ad_zip
from access_review_engine.storage import Repository
from ad_test_helpers import zip_fixture


def test_same_zip_import_is_idempotent_at_normalized_model_level(tmp_path: Path) -> None:
    first = import_ad_zip(zip_fixture(tmp_path, "standard"))
    second = import_ad_zip(zip_fixture(tmp_path, "standard"))
    assert {(i.provider, i.identifier, i.native_id) for i in first.identities} == {
        (i.provider, i.identifier, i.native_id) for i in second.identities
    }
    assert {(a.provider, a.name) for a in first.accesses} == {(a.provider, a.name) for a in second.accesses}
    assert {a.comparison_key() + (a.origin.raw["membership_type"],) for a in first.assignments} == {
        a.comparison_key() + (a.origin.raw["membership_type"],) for a in second.assignments
    }


def test_provider_scoped_assignment_replacement_does_not_delete_other_providers(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        repo.replace_assignments([
            AccessAssignment("corp-ad", "a", "corp-ad", "u", Origin("group", True, False)),
        ])
        repo.replace_assignments([
            AccessAssignment("europe-ad", "b", "europe-ad", "u", Origin("group", True, False)),
        ])
        rows = repo.list_payloads("access_assignments")
        assert {row["provider"] for row in rows} == {"corp-ad", "europe-ad"}
    finally:
        repo.close()
