from __future__ import annotations

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from access_review_engine.importers.keycloak import import_keycloak_zip
from access_review_engine.services import calculate_effective_accesses

FIXTURE = Path(__file__).parents[1] / "fixtures" / "keycloak"


def _artifact(tmp_path: Path) -> Path:
    output = tmp_path / "keycloak.zip"
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        for path in sorted(FIXTURE.iterdir()):
            archive.writestr(path.name, path.read_bytes())
    return output


def test_keycloak_v0_normalizes_objects_and_preserves_native_ids(tmp_path: Path) -> None:
    result = import_keycloak_zip(_artifact(tmp_path))

    assert result.provider.type == "keycloak"
    assert result.batch.completeness == "full"
    assert {item.native_id for item in result.identities} >= {"u-alice", "g-finance", "u-backup"}
    assert (
        next(item for item in result.identities if item.native_id == "u-backup").type
        == "technical_account"
    )
    assert (
        next(item for item in result.identities if item.native_id == "u-charlie").status
        == "disabled"
    )
    assert {item.control_object.native_id for item in result.accesses if item.control_object} >= {
        "rr-accountant", "cr-crm-admin", "cr-erp-admin"
    }
    assert (
        len(
            [
                item
                for item in result.accesses
                if item.control_object
                and item.control_object.native_id in {"cr-crm-admin", "cr-erp-admin"}
            ]
        )
        == 2
    )


def test_keycloak_v0_effective_access_keeps_direct_and_inherited_paths(tmp_path: Path) -> None:
    result = import_keycloak_zip(_artifact(tmp_path))
    evaluation = calculate_effective_accesses(
        result.assignments, result.access_relations, result.accesses
    )

    bob = [item for item in evaluation.effective_accesses if item.identity_identifier == "bob"]
    accountant = next(item for item in bob if item.access_name.endswith("rr-accountant"))
    assert accountant.direct is True
    assert len(accountant.paths) >= 2
    assert any(path.relation_ids for path in accountant.paths)
    assert any(not item.direct for item in bob if item.access_name.endswith("rr-invoice-read"))

    alice = [item for item in evaluation.effective_accesses if item.identity_identifier == "alice"]
    assert any(item.access_name == "client:c-crm:role:cr-sales" and item.direct for item in alice)
    assert any(item.access_name.endswith("rr-accountant") for item in alice)
    assert any(item.access_name.endswith("rr-invoice-read") for item in alice)

    charlie = [
        item for item in evaluation.effective_accesses if item.identity_identifier == "charlie"
    ]
    role_x = next(item for item in charlie if item.access_name.endswith("rr-role-x"))
    assert len(role_x.paths) == 2
    assert any(item["type"] == "cycle_detected" for item in evaluation.diagnostics)


def test_keycloak_v0_service_account_role_mapping_is_not_human(tmp_path: Path) -> None:
    result = import_keycloak_zip(_artifact(tmp_path))
    evaluation = calculate_effective_accesses(
        result.assignments, result.access_relations, result.accesses
    )

    service = next(item for item in result.identities if item.native_id == "u-backup")
    assert service.type == "technical_account"
    assert any(
        item.identity_identifier == service.identifier
        and item.access_name == "client:c-crm:role:cr-backup"
        for item in evaluation.effective_accesses
    )


def test_keycloak_v0_replay_is_deterministic(tmp_path: Path) -> None:
    first = import_keycloak_zip(_artifact(tmp_path))
    second = import_keycloak_zip(_artifact(tmp_path))

    def projection(result):
        return {
            "identities": sorted(
                (item.identifier, item.native_id, item.type, item.status)
                for item in result.identities
            ),
            "accesses": sorted(
                (
                    item.provider,
                    item.name,
                    item.control_object.native_id if item.control_object else None,
                )
                for item in result.accesses
            ),
            "assignments": sorted(
                (item.access_name, item.identity_identifier, item.origin.fingerprint())
                for item in result.assignments
            ),
            "relations": sorted(item.key() for item in result.access_relations or []),
        }

    assert projection(first) == projection(second)
