from access_review_engine.domain import (
    Access,
    AccessAssignment,
    AccessRelation,
    AccessRelationType,
    AssignmentType,
    Identity,
    IdentityType,
    Origin,
    Permission,
    Provider,
)
from access_review_engine.services import calculate_effective_accesses, create_snapshot
from access_review_engine.snapshot_composition import compose_snapshots, _resolve_composite_assignment


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


def test_composition_resolves_old_gcp_principal_after_workspace_import():
    workspace = Provider("workspace", "google_workspace")
    gcp = Provider("gcp", "gcp_iam")
    alice = Identity("workspace", "alice@example.com", IdentityType.USER_ACCOUNT, "active")
    developers = Identity(
        "workspace", "developers@example.com", IdentityType.GROUP, "active", native_id="dev"
    )
    cloud_admins = Identity(
        "workspace", "cloud-admins@example.com", IdentityType.GROUP, "active", native_id="cloud"
    )
    unresolved = Identity(
        "gcp", "cloud-admins@example.com", IdentityType.GROUP, "unknown", metadata={"unresolved": True}
    )
    dev_access = Access(
        "google-group:dev:MEMBER",
        "workspace",
        metadata={"membership_role": "MEMBER", "source_group": "developers@example.com"},
    )
    cloud_access = Access(
        "google-group:cloud:MEMBER",
        "workspace",
        metadata={"membership_role": "MEMBER", "source_group": "cloud-admins@example.com"},
    )
    editor = Access("gcp-iam:editor", "gcp", permission=Permission("roles/editor"))
    workspace_snapshot = create_snapshot(
        [workspace],
        [alice, developers, cloud_admins],
        [],
        [dev_access, cloud_access],
        [
            AccessAssignment(
                "workspace",
                dev_access.name,
                "workspace",
                alice.identifier,
                Origin(AssignmentType.GROUP, True, False, "developers@example.com"),
            )
        ],
        ["workspace-import-2"],
        access_relations=[
            AccessRelation(
                "workspace",
                dev_access.name,
                "workspace",
                cloud_access.name,
                AccessRelationType.GRANTS,
                Origin(AssignmentType.GROUP, False, True, "developers@example.com"),
            )
        ],
    )
    gcp_snapshot = create_snapshot(
        [gcp],
        [unresolved],
        [],
        [editor],
        [
            AccessAssignment(
                "gcp",
                editor.name,
                "gcp",
                unresolved.identifier,
                Origin(
                    AssignmentType.POLICY,
                    True,
                    False,
                    "projects/prod",
                    {"principal": "group:cloud-admins@example.com", "unresolved": True},
                ),
            )
        ],
        ["gcp-import-1"],
    )
    assert any(item.identifier == "cloud-admins@example.com" for item in workspace_snapshot.identities)
    assert gcp_snapshot.access_assignments[0].origin.raw["unresolved"] is True
    from access_review_engine.snapshot_composition import _resolve_composite_assignment

    resolved_probe = _resolve_composite_assignment(
        gcp_snapshot.access_assignments[0], workspace_snapshot.identities, workspace_snapshot.providers
    )
    assert resolved_probe.identity_provider == "workspace"

    composed = compose_snapshots(
        [gcp_snapshot, workspace_snapshot], ["workspace", "gcp"], ["full", "full"]
    )
    effective = calculate_effective_accesses(
        composed.access_assignments, composed.access_relations, composed.accesses
    )
    assert any(
        assignment.identity_provider == "workspace"
        and assignment.identity_identifier == "cloud-admins@example.com"
        for assignment in composed.access_assignments
    )
    assert any(
        item.identity_identifier == "alice@example.com"
        and item.access_name == editor.name
        and item.direct is False
        for item in effective.effective_accesses
    )
    assert not any(
        item.identity_identifier == "alice@example.com" and item.access_name == editor.name
        for item in composed.access_assignments
    )
    assert gcp_snapshot.access_assignments[0].origin.raw.get("unresolved") is True
    assert "composite_resolved" not in gcp_snapshot.access_assignments[0].origin.raw


def test_composition_prefers_workspace_identity_over_other_idps():
    ad = Provider("ad", "active_directory")
    workspace = Provider("workspace", "google_workspace")
    gcp = Provider("gcp", "gcp_iam")
    identities = [
        Identity("ad", "alice@example.com", IdentityType.USER_ACCOUNT, "active"),
        Identity("workspace", "alice@example.com", IdentityType.USER_ACCOUNT, "active"),
    ]
    assignment = AccessAssignment(
        "gcp",
        "gcp-access",
        "gcp",
        "alice@example.com",
        Origin("policy", True, False, "projects/p", {"principal": "user:alice@example.com", "unresolved": True}),
    )
    from access_review_engine.snapshot_composition import _resolve_composite_assignment

    resolved = _resolve_composite_assignment(
        assignment, identities, [ad, workspace, gcp]
    )
    assert resolved.identity_provider == "workspace"


def test_composition_keeps_ambiguous_workspace_principal_unresolved():
    workspace_a = Provider("workspace-a", "google_workspace")
    workspace_b = Provider("workspace-b", "google_workspace")
    assignment = AccessAssignment(
        "gcp",
        "gcp-access",
        "gcp",
        "alice@example.com",
        Origin("policy", True, False, "projects/p", {"principal": "user:alice@example.com", "unresolved": True}),
    )
    identities = [
        Identity("workspace-a", "alice@example.com", IdentityType.USER_ACCOUNT, "active"),
        Identity("workspace-b", "alice@example.com", IdentityType.USER_ACCOUNT, "active"),
    ]
    from access_review_engine.snapshot_composition import _resolve_composite_assignment

    resolved = _resolve_composite_assignment(
        assignment, identities, [workspace_a, workspace_b]
    )
    assert resolved.identity_provider == "gcp"
    assert resolved.origin.raw.get("unresolved") is True
    assert resolved.origin.raw.get("ambiguous") is True


def test_composition_does_not_fallback_to_non_google_identity():
    ad = Provider("ad", "active_directory")
    assignment = AccessAssignment(
        "gcp", "gcp-access", "gcp", "alice@example.com",
        Origin("policy", True, False, "projects/p", {"principal": "user:alice@example.com", "unresolved": True}),
    )
    resolved = _resolve_composite_assignment(
        assignment,
        [Identity("ad", "alice@example.com", IdentityType.USER_ACCOUNT, "active")],
        [ad],
    )
    assert resolved.identity_provider == "gcp"
    assert resolved.origin.raw.get("unresolved") is True
