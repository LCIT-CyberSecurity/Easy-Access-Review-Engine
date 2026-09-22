from __future__ import annotations

from access_review_engine.domain import Capability, PermissionCapabilityMapping
from access_review_engine.storage import Repository


def test_capability_catalogue_and_mappings_survive_restart_and_used_entries_cannot_be_deleted(
    tmp_path,
) -> None:
    path = tmp_path / "capabilities.db"
    repo = Repository(path)
    capability = Capability("export", "Export", "Export business records.")
    mapping = PermissionCapabilityMapping("aws-prod", "s3:GetObject", ("export",))
    try:
        repo.save_capability(capability)
        repo.save_permission_capability_mapping(mapping)
    finally:
        repo.close()

    reopened = Repository(path)
    try:
        assert [item for item in reopened.list_capabilities() if item.id == "export"] == [
            capability
        ]
        assert reopened.list_permission_capability_mappings() == [mapping]
        try:
            reopened.delete_capability("export")
        except ValueError as exc:
            assert "deactivate" in str(exc)
        else:
            raise AssertionError("used capabilities must not be destructively deleted")
        reopened.save_capability(Capability("export", "Export data", "Export business records."))
        assert (
            next(item for item in reopened.list_capabilities() if item.id == "export").id
            == "export"
        )
    finally:
        reopened.close()
