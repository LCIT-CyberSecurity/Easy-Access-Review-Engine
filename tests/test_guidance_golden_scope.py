from access_review_engine.api import _golden_version_provider_domains


def test_golden_scope_uses_current_expected_content() -> None:
    from_scratch_descendant = {
        "id": "v2", "source_type": "manual", "source_snapshot_id": None,
        "assignments": [{"access_provider": "crm", "identity_provider": "crm"}],
    }
    out_of_scope = {
        "id": "v3", "source_type": "from_scratch", "source_snapshot_id": None,
        "assignments": [{"access_provider": "aws", "identity_provider": "aws"}],
    }
    assert _golden_version_provider_domains(from_scratch_descendant) == {"crm"}
    assert _golden_version_provider_domains(out_of_scope) == {"aws"}


def test_golden_scope_includes_all_expected_provider_roles() -> None:
    version = {
        "assignments": [{"access_provider": "crm", "identity_provider": "ad"}],
        "expected_access_definitions": [{"provider": "ldap"}],
        "expected_access_relations": [{"parent_provider": "crm", "child_provider": "aws"}],
        "functional_access_models": [{"access_provider": "db"}],
        "access_comments": [{"access_provider": "s3"}],
    }
    assert _golden_version_provider_domains(version) == {"crm", "ad", "ldap", "aws", "db", "s3"}
