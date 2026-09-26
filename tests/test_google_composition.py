from access_review_engine.domain import (
    Access,
    AccessAssignment,
    Identity,
    IdentityType,
    Origin,
    Permission,
    Provider,
)
from access_review_engine.services import calculate_effective_accesses, create_snapshot
from access_review_engine.snapshot_composition import compose_snapshots


def test_composition_derives_workspace_group_to_gcp_access_without_fake_assignment():
    workspace = Provider("workspace", "google_workspace")
    gcp = Provider("gcp", "gcp_iam")
    group = Identity(
        "workspace", "cloud-admins@example.com", IdentityType.GROUP, "active", native_id="g1"
    )
    member_access = Access(
        "google-group:g1:MEMBER",
        "workspace",
        metadata={"membership_role": "MEMBER", "source_group": "cloud-admins@example.com"},
    )
    cloud_access = Access("gcp-iam:editor", "gcp", permission=Permission("roles/editor"))
    direct = AccessAssignment(
        "gcp",
        "gcp-iam:editor",
        "workspace",
        group.identifier,
        Origin(
            "policy", True, False, "projects/p", {"principal": "group:cloud-admins@example.com"}
        ),
    )
    snapshot = create_snapshot(
        [workspace, gcp],
        [group],
        [],
        [member_access, cloud_access],
        [direct],
        ["w-import", "g-import"],
        access_relations=[],
    )
    composed = compose_snapshots([snapshot], ["workspace", "gcp"], ["full", "full"])
    assert any(
        relation.parent_access_name == member_access.name
        and relation.child_access_name == cloud_access.name
        for relation in composed.access_relations
    )
    effective = calculate_effective_accesses(
        [
            AccessAssignment(
                "workspace",
                member_access.name,
                "workspace",
                group.identifier,
                Origin("membership", True, False),
            )
        ],
        composed.access_relations,
        composed.accesses,
    )
    assert any(item.access_name == cloud_access.name for item in effective.effective_accesses)
    assert not any(
        item.identity_identifier == "alice@example.com" and item.access_name == cloud_access.name
        for item in composed.access_assignments
    )


def test_composition_keeps_weakest_completeness_and_source_ids():
    workspace = Provider("workspace", "google_workspace")
    snapshot = create_snapshot(
        [workspace],
        [],
        [],
        [],
        [],
        ["import-1"],
        import_scope={"type": "providers", "values": ["workspace"], "completeness": "full"},
    )
    composed = compose_snapshots([snapshot], ["workspace"], ["scoped"])
    assert composed.source_import_ids == ["import-1"]
    assert composed.comparison_states is not None
