from __future__ import annotations

from pathlib import Path

from access_review_engine.domain import Identity, IdentityStatus, IdentityType
from access_review_engine.importers.ad import import_ad_zip
from ad_test_helpers import zip_fixture


def test_cross_domain_resolution_uses_native_sid_not_login(tmp_path: Path) -> None:
    europe = Identity(
        provider="europe-ad",
        identifier="jean.dupont",
        native_id="S-1-5-21-900-800-700-1501",
        type=IdentityType.USER_ACCOUNT,
        status=IdentityStatus.ACTIVE,
    )
    result = import_ad_zip(zip_fixture(tmp_path, "standard"), known_identities=[europe])
    assignment = [a for a in result.assignments if a.access_name == "GG_FOREIGN:member"][0]
    assert assignment.identity_provider == "europe-ad"
    assert assignment.identity_identifier == "jean.dupont"
