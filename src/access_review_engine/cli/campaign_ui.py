from __future__ import annotations

from access_review_engine.domain import Decision, ReviewItem
from access_review_engine.services import create_decision, latest_decisions


def run_campaign_review(items: list[ReviewItem], decisions: list[Decision]) -> list[Decision]:
    pending_decisions = list(decisions)
    while True:
        latest = latest_decisions(pending_decisions)
        _print_items(items, latest)
        print("\nActions:")
        print("A Approve")
        print("R Revoke")
        print("N Not applicable")
        print("C Comment")
        print("S Save")
        print("Q Quit")
        choice = input("Action: ").strip().lower()
        if choice in {"a", "r", "n", "c"}:
            item = _select_item(items)
            if item is None:
                continue
            if choice == "c":
                previous = latest.get(item.id)
                value = previous.value if previous else "approve"
                comment = input("Comment: ").strip() or (previous.comment if previous else None)
            else:
                value = {"a": "approve", "r": "revoke", "n": "not_applicable"}[choice]
                comment = input("Comment: ").strip() or None
            decided_by = input("Reviewer: ").strip() or None
            try:
                pending_decisions.append(create_decision(item, value, comment, decided_by))
            except ValueError as exc:
                print(exc)
        elif choice == "s":
            return pending_decisions[len(decisions):]
        elif choice == "q":
            print("No decisions saved.")
            return []
        else:
            print("Unknown action.")


def _print_items(items: list[ReviewItem], decisions: dict[str, Decision]) -> None:
    print("\n#  Identity        Access                Classification       Reviewer          Decision")
    if not items:
        print("(no review items)")
        return
    for idx, item in enumerate(items, start=1):
        decision = decisions.get(item.id)
        reviewer = (
            f"{item.reviewer.provider}/{item.reviewer.identity}"
            if item.reviewer
            else ""
        )
        print(
            f"{idx:<2} {item.identity_identifier:<15} {item.access_name:<21} "
            f"{item.classification:<20} {reviewer:<17} {decision.value if decision else 'pending'}"
        )


def _select_item(items: list[ReviewItem]) -> ReviewItem | None:
    value = input("Review item row/id: ").strip()
    if not value:
        return None
    for item in items:
        if item.id == value:
            return item
    try:
        index = int(value) - 1
    except ValueError:
        print("Review item not found.")
        return None
    if index < 0 or index >= len(items):
        print("Review item not found.")
        return None
    return items[index]
