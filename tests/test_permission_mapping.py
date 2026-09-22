from access_review_engine.domain import PermissionCapabilityMapping
from access_review_engine.services import map_native_permission


def test_mapping_is_explicit_provider_scoped_and_many_to_many_without_rewriting_native_values() -> (
    None
):
    mappings = [
        PermissionCapabilityMapping("postgres", "SELECT", ("read",)),
        PermissionCapabilityMapping("postgres", "UPDATE", ("write", "audit")),
        PermissionCapabilityMapping("postgres", "INSERT", ("write",)),
    ]
    assert map_native_permission("postgres", "SELECT", mappings) == ("read",)
    assert map_native_permission("postgres", "UPDATE", mappings) == ("audit", "write")
    assert map_native_permission("postgres", "member", mappings) == ()
    assert map_native_permission("other-provider", "SELECT", mappings) == ()
