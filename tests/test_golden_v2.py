from __future__ import annotations


from access_review_engine.domain import (
    ExpectedAccessModel,
    FunctionalModelCompleteness,
    FunctionalRight,
    GoldenAccessComment,
    GoldenSource,
    GoldenSourceAssignment,
    Target,
)
from access_review_engine.services import create_golden_version
from access_review_engine.storage import Repository, hydrate_golden_version


def test_golden_v1_is_not_defined_and_v2_round_trips_frozen_rights(tmp_path) -> None:
    source = GoldenSource("functional")
    legacy = hydrate_golden_version(
        {
            "golden_source_id": source.id,
            "version": 1,
            "source_type": "legacy",
            "checksum": "historical",
            "assignments": [],
            "id": "legacy-version",
            "created_at": "historical-time",
        }
    )
    assert legacy.schema_version == 1
    assert legacy.functional_access_models == []

    model = ExpectedAccessModel(
        "openldap-corp",
        "GG-CRM-Compta",
        FunctionalModelCompleteness.PARTIAL,
        (FunctionalRight(Target(resource={"identifier": "invoices"}), "write"),),
    )
    version = create_golden_version(
        source,
        [GoldenSourceAssignment("openldap-corp", "GG-CRM-Compta", "entra", "alice")],
        "manual",
        schema_version=2,
        functional_access_models=[model],
        access_comments=[
            GoldenAccessComment("openldap-corp", "GG-CRM-Compta", "Accounting access")
        ],
    )
    repo = Repository(tmp_path / "golden-v2.db")
    try:
        repo.upsert("golden_source_versions", version)
        payload = repo.get_payload("golden_source_versions", version.id)
        assert payload is not None
    finally:
        repo.close()
    hydrated = hydrate_golden_version(payload)
    assert hydrated.schema_version == 2
    assert hydrated.functional_access_models == [model]
    assert hydrated.access_comments[0].comment == "Accounting access"
    assert hydrated.checksum == version.checksum
