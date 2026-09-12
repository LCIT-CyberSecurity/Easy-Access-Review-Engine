from __future__ import annotations

from copy import deepcopy

from access_review_engine.application import _reconcile_accesses, persist_import_result
from access_review_engine.domain import (
    Access,
    AccessAssignment,
    AccessRelation,
    AccessRelationType,
    ControlObject,
    GoldenSourceAssignment,
    Identity,
    IdentityStatus,
    IdentityType,
    ImportBatch,
    Origin,
    Permission,
    Provider,
    ProviderType,
    Target,
)
from access_review_engine.importers.ad import ImportResult
from access_review_engine.services import (
    create_golden_source,
    create_snapshot,
    promote_snapshot,
)
from access_review_engine.storage import Repository, hydrate_snapshot


def _provider() -> Provider:
    return Provider("fixture", ProviderType.GENERIC)


def _identity(identifier: str = "alice", native_id: str | None = "I-1") -> Identity:
    return Identity("fixture", identifier, IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE, native_id=native_id)


def _access(name: str, native_id: str | None = None, permission: str | None = None) -> Access:
    return Access(
        name,
        "fixture",
        ControlObject("entitlement", name, native_id=native_id) if native_id else None,
        Permission(permission) if permission is not None else None,
    )


def _relation(parent: str, child: str) -> AccessRelation:
    return AccessRelation(
        "fixture", parent, "fixture", child, AccessRelationType.GRANTS,
        Origin("fixture", False, True, "hardening-test"),
    )


def _assignment(access_name: str = "A") -> AccessAssignment:
    return AccessAssignment("fixture", access_name, "fixture", "alice", Origin("direct", True, False, "test"))


def _result(
    accesses: list[Access],
    relations: list[AccessRelation] | None,
    *,
    completeness: str = "full",
    identities: list[Identity] | None = None,
    assignments: list[AccessAssignment] | None = None,
) -> ImportResult:
    provider = _provider()
    scope = {"type": "providers", "values": [provider.name], "completeness": completeness}
    batch = ImportBatch(provider.name, "hardening", "completed", completeness, scope, "hardening")
    return ImportResult(
        batch=batch,
        provider=provider,
        identities=identities if identities is not None else [_identity()],
        accesses=accesses,
        assignments=assignments if assignments is not None else [],
        access_relations=relations,
    )


def _relation_keys(repo: Repository) -> set[tuple[str, str]]:
    return {
        (row["parent_access_name"], row["child_access_name"])
        for row in repo.list_payloads("access_relations")
    }


def test_ct01_none_relations_preserve_existing_graph(tmp_path) -> None:
    repo = Repository(tmp_path / "ct01.db")
    try:
        accesses = [_access("A"), _access("B")]
        persist_import_result(repo, _result(accesses, [_relation("A", "B")]))
        persist_import_result(repo, _result(accesses, None))
        assert _relation_keys(repo) == {("A", "B")}
    finally:
        repo.close()


def test_ct02_empty_full_relations_clear_authoritative_graph(tmp_path) -> None:
    repo = Repository(tmp_path / "ct02.db")
    try:
        accesses = [_access("A"), _access("B")]
        persist_import_result(repo, _result(accesses, [_relation("A", "B")]))
        persist_import_result(repo, _result(accesses, []))
        assert _relation_keys(repo) == set()
    finally:
        repo.close()


def test_ct03_scoped_relation_observation_is_additive(tmp_path) -> None:
    repo = Repository(tmp_path / "ct03.db")
    try:
        accesses = [_access(name) for name in ("A", "B", "C", "D", "X")]
        persist_import_result(repo, _result(accesses, [_relation("A", "B"), _relation("C", "D")]))
        scoped = _result(accesses, [_relation("A", "X")], completeness="scoped")
        scoped.batch.scope["completeness"] = "scoped"
        persist_import_result(repo, scoped)
        assert _relation_keys(repo) == {("A", "B"), ("C", "D"), ("A", "X")}
    finally:
        repo.close()


def test_ct04_full_relations_replace_provider_graph(tmp_path) -> None:
    repo = Repository(tmp_path / "ct04.db")
    try:
        accesses = [_access(name) for name in ("A", "B", "X")]
        persist_import_result(repo, _result(accesses, [_relation("A", "B")]))
        persist_import_result(repo, _result(accesses, [_relation("A", "X")]))
        assert _relation_keys(repo) == {("A", "X")}
    finally:
        repo.close()


def test_ct05_same_access_key_with_incompatible_definition_collides() -> None:
    existing = _access("Reader", native_id="A", permission="read")
    incoming = _access("Reader", native_id="B", permission="write")
    try:
        _reconcile_accesses([existing], [incoming])
    except ValueError as exc:
        assert "ACCESS_DEFINITION_COLLISION" in str(exc)
    else:
        raise AssertionError("expected ACCESS_DEFINITION_COLLISION")


def test_ct06_compatible_duplicate_accesses_are_deduplicated() -> None:
    access = _access("Reader", native_id="A", permission="read")
    result = _reconcile_accesses([], [access, deepcopy(access)])
    assert len(result) == 1


def test_ct07_access_key_does_not_allow_last_write_wins() -> None:
    first = _access("Reader", native_id="A", permission="read")
    second = _access("Reader", native_id="B", permission="write")
    try:
        _reconcile_accesses([], [first, second])
    except ValueError as exc:
        assert "ACCESS_DEFINITION_COLLISION" in str(exc)
    else:
        raise AssertionError("expected ACCESS_DEFINITION_COLLISION")


def test_ct08_collision_rolls_back_all_business_state(tmp_path) -> None:
    repo = Repository(tmp_path / "ct08.db")
    try:
        result = _result(
            [_access("Good"), _access("Reader", native_id="A", permission="read"), _access("Reader", native_id="B", permission="write")],
            None,
            identities=[_identity("new-user", "I-2")],
            assignments=[_assignment("Good")],
        )
        try:
            persist_import_result(repo, result)
        except ValueError as exc:
            assert "ACCESS_DEFINITION_COLLISION" in str(exc)
        else:
            raise AssertionError("expected ACCESS_DEFINITION_COLLISION")
        for table in ("providers", "imports", "identities", "accesses", "access_assignments", "access_relations", "snapshots"):
            assert repo.list_payloads(table) == []
    finally:
        repo.close()


class _FailingSnapshotRepository(Repository):
    def insert_append_only(self, table, obj) -> None:
        if table == "snapshots":
            raise RuntimeError("forced snapshot persistence failure")
        super().insert_append_only(table, obj)


def test_ct09_persistence_failure_rolls_back(tmp_path) -> None:
    repo = _FailingSnapshotRepository(tmp_path / "ct09.db")
    try:
        try:
            persist_import_result(repo, _result([_access("A")], None))
        except RuntimeError as exc:
            assert "forced" in str(exc)
        else:
            raise AssertionError("expected persistence failure")
        assert repo.list_payloads("providers") == []
        assert repo.list_payloads("imports") == []
        assert repo.list_payloads("identities") == []
        assert repo.list_payloads("accesses") == []
        assert repo.list_payloads("snapshots") == []
    finally:
        repo.close()


def test_ct10_golden_round_trip_keeps_permission_none(tmp_path) -> None:
    repo = Repository(tmp_path / "ct10.db")
    try:
        access = _access("PREMIUM_USER", native_id="123")
        assignment = _assignment("PREMIUM_USER")
        first = persist_import_result(repo, _result([access], None, assignments=[assignment]))
        golden = promote_snapshot(create_golden_source("baseline"), first)
        repo2 = Repository(tmp_path / "ct10-reload.db")
        try:
            second = persist_import_result(repo2, _result([_access("PREMIUM_USER", native_id="123")], None, assignments=[_assignment("PREMIUM_USER")]), golden)
            restored = hydrate_snapshot(repo2.list_payloads("snapshots")[-1])
            assert any(row["classification"] == "expected_and_observed" for row in restored.comparison_states)
            assert golden.assignments[0].access_permission is None
            assert restored.accesses[0].permission is None
            assert second.checksum == restored.checksum
        finally:
            repo2.close()
    finally:
        repo.close()


def test_ct11_golden_legacy_key_without_native_id_matches() -> None:
    snapshot = create_snapshot(
        [_provider()], [_identity(native_id=None)], [], [_access("PREMIUM_USER")], [_assignment("PREMIUM_USER")], ["i-1"]
    )
    golden = promote_snapshot(create_golden_source("legacy"), snapshot)
    assert golden.assignments[0].stable_key() is None
    compared = create_snapshot(
        [_provider()], [_identity(native_id=None)], [], [_access("PREMIUM_USER")], [_assignment("PREMIUM_USER")], ["i-2"], golden
    )
    assert compared.comparison_states[0]["classification"] == "expected_and_observed"


def test_ct12_member_is_not_a_permission_none_fallback() -> None:
    opaque = GoldenSourceAssignment("p", "A", "p", "i", "123", None, "I")
    member = GoldenSourceAssignment("p", "A", "p", "i", "123", "member", "I")
    assert opaque.stable_key() != member.stable_key()


def test_ct13_legacy_snapshot_without_relations_is_readable() -> None:
    snapshot = create_snapshot([], [], [], [], [], ["i-1"])
    payload = snapshot.__dict__.copy()
    payload.pop("access_relations")
    assert hydrate_snapshot(payload).access_relations == []


def test_ct14_legacy_import_without_relations_is_conservative() -> None:
    result = _result([], None)
    assert result.access_relations is None
