from __future__ import annotations

from collections.abc import Iterable

from access_review_engine.domain import GoldenSourceAssignment, GoldenSource, GoldenSourceVersion
from access_review_engine.services import create_golden_version


def run_golden_editor(
    source: GoldenSource,
    current_version: GoldenSourceVersion | None,
    versions: Iterable[GoldenSourceVersion],
) -> GoldenSourceVersion | None:
    assignments = list(current_version.assignments) if current_version else []
    draft_version = max((item.version for item in versions), default=0) + 1
    current_label = f"v{current_version.version}" if current_version else "none"
    filter_text = ""
    print(f"Golden Source: {source.name}")
    print(f"Current version: {current_label}")
    print(f"Draft version: v{draft_version}")
    while True:
        _print_assignments(assignments, filter_text)
        print("\nCommands:")
        print("A Add")
        print("E Edit")
        print("D Delete")
        print("/ Search")
        print("F Filter")
        print("S Save")
        print("Q Quit")
        choice = input("Command: ").strip().lower()
        if choice == "a":
            assignments.append(_prompt_assignment())
        elif choice == "e":
            index = _prompt_index(assignments)
            if index is not None:
                assignments[index] = _prompt_assignment(assignments[index])
        elif choice == "d":
            index = _prompt_index(assignments)
            if index is not None:
                removed = assignments.pop(index)
                print(f"deleted {removed.identity_provider}/{removed.identity_identifier} -> {removed.access_provider}/{removed.access_name}")
        elif choice == "/":
            filter_text = input("Search: ").strip().lower()
        elif choice == "f":
            filter_text = input("Filter text: ").strip().lower()
        elif choice == "s":
            parent_id = current_version.id if current_version else None
            return create_golden_version(
                source,
                assignments,
                "interactive_edit",
                versions,
                parent_version_id=parent_id,
                comment="Interactive edit",
            )
        elif choice == "q":
            print("No Golden Source version created.")
            return None
        else:
            print("Unknown command.")


def _print_assignments(assignments: list[GoldenSourceAssignment], filter_text: str = "") -> None:
    print("\n#  Identity        Identity Provider  Access                Access Provider  Permission")
    visible = [
        (idx, item)
        for idx, item in enumerate(assignments, start=1)
        if not filter_text or filter_text in " ".join(_row_values(item)).lower()
    ]
    if not visible:
        print("(no assignments)")
        return
    for idx, item in visible:
        permission = item.access_permission or "member"
        print(
            f"{idx:<2} {item.identity_identifier:<15} {item.identity_provider:<18} "
            f"{item.access_name:<21} {item.access_provider:<16} {permission}"
        )


def _row_values(item: GoldenSourceAssignment) -> list[str]:
    return [
        item.identity_identifier,
        item.identity_provider,
        item.access_name,
        item.access_provider,
        item.access_permission or "",
        item.identity_native_id or "",
        item.access_native_id or "",
    ]


def _prompt_index(assignments: list[GoldenSourceAssignment]) -> int | None:
    if not assignments:
        print("No assignments.")
        return None
    value = input("Row number: ").strip()
    try:
        index = int(value) - 1
    except ValueError:
        print("Invalid row number.")
        return None
    if index < 0 or index >= len(assignments):
        print("Row number out of range.")
        return None
    return index


def _prompt_assignment(current: GoldenSourceAssignment | None = None) -> GoldenSourceAssignment:
    access_provider = _prompt("Access provider", current.access_provider if current else None)
    access_name = _prompt("Access", current.access_name if current else None)
    identity_provider = _prompt("Identity provider", current.identity_provider if current else None)
    identity_identifier = _prompt("Identity", current.identity_identifier if current else None)
    access_permission = _prompt_optional("Permission", current.access_permission if current else "member")
    access_native_id = _prompt_optional("Access native id", current.access_native_id if current else None)
    identity_native_id = _prompt_optional("Identity native id", current.identity_native_id if current else None)
    return GoldenSourceAssignment(
        access_provider=access_provider,
        access_name=access_name,
        identity_provider=identity_provider,
        identity_identifier=identity_identifier,
        access_permission=access_permission,
        access_native_id=access_native_id,
        identity_native_id=identity_native_id,
    )


def _prompt(label: str, current: str | None = None) -> str:
    while True:
        suffix = f" [{current}]" if current else ""
        value = input(f"{label}{suffix}: ").strip()
        if value:
            return value
        if current:
            return current
        print(f"{label} is required.")


def _prompt_optional(label: str, current: str | None = None) -> str | None:
    suffix = f" [{current}]" if current else ""
    value = input(f"{label}{suffix}: ").strip()
    if value:
        return value
    return current
