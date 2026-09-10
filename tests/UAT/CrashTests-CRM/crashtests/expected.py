from __future__ import annotations

from access_review_engine.domain import ComparisonState, Snapshot


def state(snapshot: Snapshot, access_name: str, identity: str) -> dict[str, object]:
    matches = [
        row
        for row in snapshot.comparison_states
        if row["access_name"] == access_name and row["identity_identifier"] == identity
    ]
    assert matches, f"missing comparison row for {identity}/{access_name}"
    assert len(matches) == 1
    return matches[0]


def classifications(snapshot: Snapshot) -> set[str]:
    return {str(row["classification"]) for row in snapshot.comparison_states}


def assert_classification(
    snapshot: Snapshot, access_name: str, identity: str, expected: ComparisonState | str
) -> None:
    row = state(snapshot, access_name, identity)
    assert row["classification"] == str(expected), {
        "expected": str(expected),
        "observed": row,
        "artifact": "tests/UAT/CrashTests-CRM/artifacts/observed.json",
    }
