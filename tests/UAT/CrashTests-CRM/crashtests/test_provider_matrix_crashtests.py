from access_review_engine.domain import (
    Access,
    AccessAssignment,
    AccessRelation,
    AccessRelationType,
    Origin,
    Permission,
    Target,
    canonical_target_key,
    target_semantically_equal,
)
from access_review_engine.services import calculate_effective_accesses


def test_ct_crm_038_same_generic_graph_calculates_ad_ldap_crm_aws_db_linux_and_cross_provider() -> (
    None
):
    fixtures = [
        ("corp-ad", "GG-Finance", "GG-Readers", "alice", "member"),
        ("openldap-corp", "cn=finance", "cn=readers", "bob", "member"),
        ("nexabyte-crm", "CRM-Admin", "Users:Admin", "carol", "users.admin"),
        ("aws-prod", "FinanceRole", "s3:GetObject", "dave", "s3:GetObject"),
        ("postgres-prod", "DB-Analyst", "public.orders:SELECT", "erin", "SELECT"),
        ("linux-prod", "ops", "sudo:/usr/bin/systemctl", "frank", "sudo"),
    ]
    for provider, root, leaf, person, native_permission in fixtures:
        direct = AccessAssignment(
            provider, root, "identity-provider", person, Origin("fixture", True, False)
        )
        grants = AccessRelation(
            provider,
            root,
            provider,
            leaf,
            AccessRelationType.GRANTS,
            Origin("fixture", False, True),
        )
        leaf_access = Access(leaf, provider, permission=Permission(native_permission))
        result = calculate_effective_accesses(
            [direct], [grants], [Access(root, provider), leaf_access]
        )
        assert any(item.access_name == leaf for item in result.effective_accesses)
        assert leaf_access.permission is not None
        assert leaf_access.permission.identifier == native_permission
        assert direct.access_name == root

    cross_provider_assignment = AccessAssignment(
        "openldap-corp", "GG-CRM-Compta", "entra", "gina", Origin("fixture", True, False)
    )
    cross_provider_grant = AccessRelation(
        "openldap-corp",
        "GG-CRM-Compta",
        "nexabyte-crm",
        "CRM-Compta",
        AccessRelationType.GRANTS,
        Origin("fixture", False, True),
    )
    cross_provider_accesses = [
        Access("GG-CRM-Compta", "openldap-corp"),
        Access("CRM-Compta", "nexabyte-crm"),
    ]
    derived = calculate_effective_accesses(
        [cross_provider_assignment], [cross_provider_grant], cross_provider_accesses
    )
    assert any(item.access_provider == "nexabyte-crm" for item in derived.effective_accesses)


def test_ct_crm_039_canonical_target_matrix_uses_only_three_generic_levels() -> None:
    targets = [
        Target(service={"identifier": "crm", "type": "application"}),
        Target(service={"identifier": "crm"}, component={"identifier": "billing"}),
        Target(
            service={"identifier": "postgresql", "display_name": "PostgreSQL"},
            component={"identifier": "salesdb", "type": "database"},
            resource={"identifier": "salesdb.public.orders", "type": "database_table"},
        ),
        Target(
            service={"identifier": "fileserver"},
            component={"identifier": "finance-share"},
            resource={"identifier": "/2026/Budget.xlsx", "type": "file"},
        ),
        Target(
            service={"identifier": "aws-prod"},
            component={"identifier": "finance"},
            resource={"identifier": "arn:aws:s3:::finance/*", "type": "bucket_object"},
        ),
        Target(
            service={"identifier": "corp-ad"},
            component={"identifier": "corp.example.com"},
            resource={"identifier": "OU=France,DC=corp,DC=example,DC=com"},
        ),
        Target(
            service={"identifier": "kubernetes-prod"},
            component={"identifier": "namespace/prod"},
            resource={"identifier": "pod/backend-123"},
        ),
    ]
    for target in targets:
        assert canonical_target_key(target)
        relabelled = Target(
            service=target.service | {"display_name": "Relabelled"} if target.service else None,
            component=target.component | {"display_name": "Relabelled"}
            if target.component
            else None,
            resource=target.resource | {"display_name": "Relabelled"} if target.resource else None,
        )
        assert target_semantically_equal(target, relabelled)
