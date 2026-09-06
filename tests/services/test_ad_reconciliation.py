from __future__ import annotations

from access_review_engine.domain import Identity, IdentityStatus, IdentityType
from access_review_engine.services import reconcile_identities


def test_ad_rename_same_sid_keeps_internal_uuid() -> None:
    existing = [
        Identity("corp-ad", "jean.dupont", IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE, native_id="S-1-5-21-1-2-3-1101")
    ]
    imported = [
        Identity("corp-ad", "jdupont", IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE, native_id="S-1-5-21-1-2-3-1101")
    ]
    merged = reconcile_identities(existing, imported, completeness="full", scope={"type": "all"})
    assert len(merged) == 1
    assert merged[0].id == existing[0].id
    assert merged[0].identifier == "jdupont"


def test_deleted_only_when_full_collection() -> None:
    existing = [
        Identity("corp-ad", "gone", IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE, native_id="S-1-5-21-1-2-3-1102")
    ]
    assert reconcile_identities(existing, [], completeness="full", scope={"type": "all"})[0].status == "deleted"
    assert reconcile_identities(existing, [], completeness="unknown", scope={"type": "all"}) == []
