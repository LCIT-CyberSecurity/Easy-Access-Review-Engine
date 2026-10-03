from access_review_engine.perimeters import (
    associate,
    create_perimeter,
    descendants,
    path,
    unassociate,
    update_perimeter,
    validate_selection,
)
from access_review_engine.storage import Repository


def test_perimeters_support_independent_trees_and_explicit_associations(tmp_path):
    with Repository(tmp_path / "perimeters.db") as repo:
        group = create_perimeter(repo, "organization", {"name": "Groupe D-Lake"})
        acgm = create_perimeter(repo, "organization", {"name": "ACGM", "parent_id": group["id"]})
        finance = create_perimeter(repo, "information_system", {"name": "Finance"})
        billing = create_perimeter(repo, "information_system", {"name": "Facturation", "parent_id": finance["id"]})

        assert [row["name"] for row in path(repo, "organization", acgm["id"])] == ["Groupe D-Lake", "ACGM"]
        assert [row["name"] for row in descendants(repo, "information_system", finance["id"])] == ["Facturation"]
        link = associate(repo, acgm["id"], finance["id"])
        assert link["organization_id"] == acgm["id"]
        assert unassociate(repo, acgm["id"], finance["id"])


def test_perimeters_reject_self_parent_and_cycles(tmp_path):
    with Repository(tmp_path / "perimeters.db") as repo:
        root = create_perimeter(repo, "organization", {"name": "Root"})
        child = create_perimeter(repo, "organization", {"name": "Child", "parent_id": root["id"]})
        try:
            update_perimeter(repo, "organization", root["id"], {"parent_id": child["id"]})
        except ValueError as exc:
            assert "cycle" in str(exc).lower()
        else:
            raise AssertionError("cycle was accepted")


def test_active_organization_requires_information_system_for_targeting(tmp_path):
    with Repository(tmp_path / "perimeters.db") as repo:
        organization = create_perimeter(repo, "organization", {"name": "ACGM"})
        try:
            validate_selection(repo, {"organizations": [organization["id"]]})
        except ValueError as exc:
            assert "associated information system" in str(exc)
        else:
            raise AssertionError("organization without an information system was targetable")
