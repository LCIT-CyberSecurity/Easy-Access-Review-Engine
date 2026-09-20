"""Versioned comments attached to expected Golden Source assignments."""
from __future__ import annotations

from dataclasses import asdict
from typing import Any, Iterable

from access_review_engine.domain import (
    GoldenSourceAssignment,
    GoldenSourceVersion,
    now_utc,
    stable_checksum,
)
from access_review_engine.storage import Repository


MAX_COMMENT_LENGTH = 4000


def assignment_annotations(repo: Repository, version_id: str) -> list[dict[str, Any]]:
    return [
        row
        for row in repo.list_payloads("golden_assignment_annotations")
        if row.get("golden_source_version_id") == version_id
    ]


def annotation_for_assignment(
    repo: Repository,
    version_id: str,
    assignment: GoldenSourceAssignment,
) -> dict[str, Any] | None:
    candidates = assignment_annotations(repo, version_id)
    stable_matches = [
        row for row in candidates if _stable_match(_assignment(row), assignment)
    ]
    if len(stable_matches) == 1:
        return stable_matches[0]
    if stable_matches:
        return None
    legacy_matches = [
        row for row in candidates if _legacy_match(_assignment(row), assignment)
    ]
    return legacy_matches[0] if len(legacy_matches) == 1 else None


def set_assignment_annotation(
    repo: Repository,
    version: GoldenSourceVersion,
    assignment: GoldenSourceAssignment,
    comment: object,
    updated_by: str | None,
) -> dict[str, Any] | None:
    cleaned = normalize_assignment_comment(comment)
    annotation_id = _annotation_id(version.id, assignment)
    if cleaned is None:
        repo.delete_ids("golden_assignment_annotations", {annotation_id})
        return None
    timestamp = now_utc()
    previous = repo.get_payload("golden_assignment_annotations", annotation_id) or {}
    record = {
        "id": annotation_id,
        "golden_source_version_id": version.id,
        "assignment": asdict(assignment),
        "comment": cleaned,
        "created_at": previous.get("created_at") or timestamp,
        "updated_at": timestamp,
        "updated_by": updated_by,
    }
    repo.upsert("golden_assignment_annotations", record)
    return record


def copy_assignment_annotations(
    repo: Repository,
    previous: GoldenSourceVersion | None,
    current: GoldenSourceVersion,
    updated_by: str | None = None,
) -> None:
    """Copy comments stable-first, falling back only when stable metadata is unavailable."""
    if previous is None:
        return
    old_rows = assignment_annotations(repo, previous.id)
    for assignment in current.assignments:
        matched = _matching_annotation(old_rows, assignment)
        if matched is not None:
            set_assignment_annotation(
                repo,
                current,
                assignment,
                matched.get("comment"),
                updated_by or str(matched.get("updated_by") or "") or None,
            )


def _matching_annotation(
    rows: Iterable[dict[str, Any]],
    assignment: GoldenSourceAssignment,
) -> dict[str, Any] | None:
    items = list(rows)
    stable = [row for row in items if _stable_match(_assignment(row), assignment)]
    if len(stable) == 1:
        return stable[0]
    if stable:
        return None
    legacy = [row for row in items if _legacy_match(_assignment(row), assignment)]
    return legacy[0] if len(legacy) == 1 else None


def _stable_match(left: GoldenSourceAssignment, right: GoldenSourceAssignment) -> bool:
    return bool(left.stable_key() and right.stable_key() and left.stable_key() == right.stable_key())


def _legacy_match(left: GoldenSourceAssignment, right: GoldenSourceAssignment) -> bool:
    if left.stable_key() is not None and right.stable_key() is not None:
        return False
    return left.key() == right.key()


def _assignment(row: dict[str, Any]) -> GoldenSourceAssignment:
    payload = row.get("assignment")
    return GoldenSourceAssignment(**payload) if isinstance(payload, dict) else GoldenSourceAssignment("", "", "", "")


def _annotation_id(version_id: str, assignment: GoldenSourceAssignment) -> str:
    return stable_checksum({"golden_source_version_id": version_id, "assignment": asdict(assignment)})


def normalize_assignment_comment(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("Golden assignment comment must be text")
    cleaned = value.strip()
    if len(cleaned) > MAX_COMMENT_LENGTH:
        raise ValueError("Golden assignment comment is too long")
    return cleaned or None
