from __future__ import annotations

def run_global_menu() -> int:
    """Run the human-facing menu while delegating every action to the CLI dispatcher."""
    from .main import dispatch, parser
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
            result = _run_line(dispatch, "analyze")
        elif choice == "3":
            result = _golden_menu(dispatch)
        elif choice == "4":
            result = _campaign_menu(dispatch)
        elif choice == "5":
            result = _run_line(dispatch, "export report --output reports")
        elif choice == "6":
            return 0
        else:
            print("Please select an option from 1 to 6.")
            continue
        if result:
            print(f"Command failed with exit code {result}.")

def _provider_menu(dispatch) -> int:
    print("\nProviders")
    print("1. List")
    print("2. Sync")
    print("3. Check")
    print("4. Collect")
    print("5. Back")
    choice = input("Select an option: ").strip()
    if choice == "5": return 0
    if choice == "1": return dispatch(parser().parse_args(["provider", "list"]))
    provider = input("Provider name: ").strip()
    if not provider: return 0
    action = {"2": "sync", "3": "check", "4": "collect"}.get(choice)
    if not action: return 0
    return dispatch(parser().parse_args(["provider", action, provider]))

def _golden_menu(dispatch) -> int:
    print("\nGolden Source")
    print("1. List")
    print("2. Show")
    print("3. Promote latest snapshot")
    print("4. Edit")
    print("5. Back")
    choice = input("Select an option: ").strip()
    if choice == "1": return dispatch(parser().parse_args(["golden", "list"]))
    if choice in {"2", "3", "4"}:
        name = input("Golden Source name: ").strip()
        if not name: return 0
        command = {"2": ["golden", "show", name], "3": ["golden", "promote", name], "4": ["golden", "edit", name]}[choice]
        return dispatch(parser().parse_args(command))
    return 0

def _campaign_menu(dispatch) -> int:
    print("\nCampaigns")
    print("1. List")
    print("2. Status")
    print("3. Export")
    print("4. Back")
    choice = input("Select an option: ").strip()
    if choice == "1": return dispatch(parser().parse_args(["campaign", "list"]))
    if choice == "2": return dispatch(parser().parse_args(["campaign", "status"]))
    if choice == "3":
        output = input("Output directory [reports]: ").strip() or "reports"
        return dispatch(parser().parse_args(["campaign", "export", output]))
    return 0

def _run_line(dispatch, line: str) -> int:
    from .main import parser
    return dispatch(parser().parse_args(line.split()))
