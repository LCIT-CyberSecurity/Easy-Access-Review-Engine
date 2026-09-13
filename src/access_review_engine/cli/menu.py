from __future__ import annotations

from collections.abc import Callable

Dispatch = Callable[[object], int]


def run_global_menu() -> int:
    """Run the human-facing menu while delegating every action to the CLI dispatcher."""
    from .main import dispatch

    while True:
        print("\nEasy Access Review Engine\n")
        print("1. Providers")
        print("2. Analyze")
        print("3. Golden Source")
        print("4. Campaigns")
        print("5. Exports")
        print("6. Quit")
        choice = input("\nSelect an option: ").strip()
        if choice == "1":
            result = _provider_menu(dispatch)
        elif choice == "2":
            result = _analyze_menu(dispatch)
        elif choice == "3":
            result = _golden_menu(dispatch)
        elif choice == "4":
            result = _campaign_menu(dispatch)
        elif choice == "5":
            result = _export_menu(dispatch)
        elif choice == "6":
            return 0
        else:
            print("Please select an option from 1 to 6.")
            continue
        if result:
            print(f"Command failed with exit code {result}.")


def _provider_menu(dispatch: Dispatch) -> int:
    print("\nProviders")
    labels = [
        "List", "Setup / Create", "Edit", "Show", "Check", "Check all",
        "Collect", "Import", "Sync", "Sync dry-run", "Sync all", "Sync all dry-run", "Back",
    ]
    for idx, label in enumerate(labels, start=1):
        print(f"{idx}. {label}")
    choice = input("Select an option: ").strip()
    if choice == "13":
        return 0
    if choice == "1":
        return _run_args(dispatch, ["provider", "list"])
    if choice == "2":
        return _run_args(dispatch, ["provider", "setup"])
    if choice in {"3", "4", "5", "7", "9", "10"}:
        provider = input("Provider name: ").strip()
        if not provider:
            return 0
        command = {
            "3": ["provider", "edit", provider],
            "4": ["provider", "show", provider],
            "5": ["provider", "check", provider],
            "7": ["provider", "collect", provider],
            "9": ["provider", "sync", provider],
            "10": ["provider", "sync", provider, "--dry-run"],
        }[choice]
        return _run_args(dispatch, command)
    if choice == "6":
        return _run_args(dispatch, ["provider", "check", "--all"])
    if choice == "8":
        path = input("Import file: ").strip()
        provider = input("Provider [openldap]: ").strip() or "openldap"
        return _run_args(dispatch, ["provider", "import", path, "--provider", provider]) if path else 0
    if choice == "11":
        return _run_args(dispatch, ["provider", "sync", "--all"])
    if choice == "12":
        return _run_args(dispatch, ["provider", "sync", "--all", "--dry-run"])
    return 0


def _analyze_menu(dispatch: Dispatch) -> int:
    print("\nAnalyze")
    print("1. Global")
    print("2. Provider")
    print("3. Identity")
    print("4. Access")
    print("5. Back")
    choice = input("Select an option: ").strip()
    if choice == "1":
        return _run_args(dispatch, ["analyze"])
    if choice == "2":
        value = input("Provider: ").strip()
        return _run_args(dispatch, ["analyze", "--provider", value]) if value else 0
    if choice == "3":
        value = input("Identity: ").strip()
        return _run_args(dispatch, ["analyze", "--identity", value]) if value else 0
    if choice == "4":
        value = input("Access: ").strip()
        return _run_args(dispatch, ["analyze", "--access", value]) if value else 0
    return 0


def _golden_menu(dispatch: Dispatch) -> int:
    print("\nGolden Source")
    labels = ["List", "Show", "Create", "Create from latest snapshot", "Import CSV", "Edit interactively", "Diff", "Export CSV", "Back"]
    for idx, label in enumerate(labels, start=1):
        print(f"{idx}. {label}")
    choice = input("Select an option: ").strip()
    if choice == "1":
        return _run_args(dispatch, ["golden", "list"])
    if choice == "9":
        return 0
    if choice in {"2", "3", "4", "5", "6", "7", "8"}:
        name = input("Golden Source name: ").strip()
        if not name:
            return 0
        if choice == "2":
            return _run_args(dispatch, ["golden", "show", name])
        if choice == "3":
            return _run_args(dispatch, ["golden", "create", name])
        if choice == "4":
            return _run_args(dispatch, ["golden", "create", name, "--from-snapshot", "latest"])
        if choice == "5":
            path = input("CSV file: ").strip()
            return _run_args(dispatch, ["golden", "import", name, path]) if path else 0
        if choice == "6":
            return _run_args(dispatch, ["golden", "edit", name])
        if choice == "7":
            return _run_args(dispatch, ["golden", "diff", name])
        output = input("Output file [auto]: ").strip()
        args = ["golden", "export", name, "--format", "csv"]
        if output:
            args.extend(["--output", output])
        return _run_args(dispatch, args)
    return 0


def _campaign_menu(dispatch: Dispatch) -> int:
    print("\nCampaigns")
    labels = ["List", "Create", "Open", "Review", "Status", "Close", "Export", "Back"]
    for idx, label in enumerate(labels, start=1):
        print(f"{idx}. {label}")
    choice = input("Select an option: ").strip()
    if choice == "1":
        return _run_args(dispatch, ["campaign", "list"])
    if choice == "8":
        return 0
    if choice in {"2", "3", "4", "5", "6", "7"}:
        name = input("Campaign name: ").strip()
        if not name and choice != "5":
            return 0
        if choice == "2":
            return _run_args(dispatch, ["campaign", "create", name])
        if choice == "3":
            return _run_args(dispatch, ["campaign", "open", name])
        if choice == "4":
            return _run_args(dispatch, ["campaign", "review", name])
        if choice == "5":
            return _run_args(dispatch, ["campaign", "status", name] if name else ["campaign", "status"])
        if choice == "6":
            return _run_args(dispatch, ["campaign", "close", name])
        output = input("Output directory [reports]: ").strip() or "reports"
        return _run_args(dispatch, ["campaign", "export", name, "--output", output])
    return 0


def _export_menu(dispatch: Dispatch) -> int:
    print("\nExports")
    print("1. Report")
    print("2. Revocations")
    print("3. Golden CSV")
    print("4. Back")
    choice = input("Select an option: ").strip()
    if choice == "1":
        campaign = input("Campaign [latest]: ").strip()
        args = ["export", "report"]
        if campaign:
            args.extend(["--campaign", campaign])
        return _run_args(dispatch, args)
    if choice == "2":
        campaign = input("Campaign [latest]: ").strip()
        args = ["export", "revocations"]
        if campaign:
            args.extend(["--campaign", campaign])
        return _run_args(dispatch, args)
    if choice == "3":
        name = input("Golden Source name: ").strip()
        return _run_args(dispatch, ["golden", "export", name, "--format", "csv"]) if name else 0
    return 0


def _run_args(dispatch: Dispatch, args: list[str]) -> int:
    from .main import parser

    return dispatch(parser().parse_args(args))
