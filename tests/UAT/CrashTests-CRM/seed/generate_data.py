#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import subprocess
from pathlib import Path


RESOURCE_FILES = {
    "customer": ["customer/company.json"],
    "contacts": ["customer/contacts.json"],
    "prospects": ["sales/prospect.json"],
    "account_owner": ["sales/account-owner.json"],
    "contracts": ["sales/signed-contracts.json"],
    "orders": ["sales/orders.json"],
    "invoices": ["finance/invoices.json"],
    "hardware": ["assets/hardware.json"],
    "serial_numbers": ["assets/serial-numbers.json"],
    "licenses": ["assets/licenses.json"],
    "support": ["support/subscriptions.json"],
    "tickets": ["support/tickets.json"],
    "shipments": ["logistics/shipments.json"],
    "replacements": ["logistics/replacements.json"],
}

ROLE_GROUPS = {
    "CRM-Compta": "crm-compta",
    "CRM-Sales": "crm-sales",
    "CRM-Logistics": "crm-logistics",
    "CRM-Support": "crm-support",
    "CRM-Admin": "crm-admin",
}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def run(args: list[str]) -> None:
    subprocess.run(args, check=True)


def ensure_group(name: str) -> None:
    if subprocess.run(["getent", "group", name], check=False).returncode != 0:
        run(["groupadd", "--system", name])


def ensure_user(row: dict[str, str]) -> None:
    username = row["username"]
    if subprocess.run(["id", "-u", username], check=False).returncode != 0:
        run(["useradd", "--system", "--create-home", "--shell", "/usr/sbin/nologin", username])
    if row["status"] == "disabled":
        run(["usermod", "--lock", username])


def ensure_memberships(assignments: list[dict[str, str]]) -> None:
    for item in assignments:
        group = ROLE_GROUPS.get(item["access"])
        if group:
            run(["usermod", "-a", "-G", group, item["identity"]])


def client_payload(client_id: str, index: int) -> dict[str, object]:
    suffix = f"{index:03d}"
    owner = ["emma.laurent", "fiona.moreau", "gabriel.petit", "hana.dubois"][index % 4]
    return {
        "company": {
            "customer_id": client_id,
            "company_name": f"NexaByte Demo Customer {suffix}",
            "status": "active" if index % 7 else "prospect",
            "account_owner": owner,
        },
        "contacts": [
            {
                "name": f"Contact {suffix} A",
                "role": "Operations Manager",
                "email": f"contact{suffix}a@example.test",
                "phone": f"+3300000{suffix}",
            },
            {
                "name": f"Contact {suffix} B",
                "role": "Finance Contact",
                "email": f"contact{suffix}b@example.test",
                "phone": f"+3300001{suffix}",
            },
        ],
        "prospect": {
            "opportunity": f"Lifecycle renewal {suffix}",
            "status": "negotiation",
            "sales_user": owner,
            "estimated_value": 10000 + index * 250,
        },
        "account_owner": {"account_owner": owner},
        "signed_contracts": [
            {
                "contract_id": f"CTR-{suffix}-001",
                "date": "2026-01-15",
                "duration_months": 36,
                "type": "support and licensing",
                "sales_user": owner,
            }
        ],
        "orders": [
            {
                "order_id": f"ORD-{suffix}-001",
                "type": "hardware",
                "product": "NexaByte Workstation Bundle",
                "quantity": 3 + index % 5,
                "status": "confirmed",
            }
        ],
        "invoices": [
            {
                "invoice_id": f"INV-{suffix}-001",
                "amount": 2400 + index * 17,
                "status": "open",
                "due_date": "2026-03-31",
            }
        ],
        "hardware": [
            {
                "equipment_id": f"EQ-{suffix}-001",
                "category": "laptop",
                "model": "NexaBook Pro Demo",
                "client": client_id,
            }
        ],
        "serial_numbers": [f"NB-CLIENT{suffix}-LAP-001"],
        "licenses": [f"DEMO-LICENSE-CLIENT{suffix}-001"],
        "subscriptions": {
            "support_level": "gold" if index % 3 else "standard",
            "start_date": "2026-01-01",
            "end_date": "2026-12-31",
            "covered_assets": [f"EQ-{suffix}-001"],
        },
        "tickets": [
            {
                "ticket_id": f"TCK-{suffix}-001",
                "severity": "medium",
                "status": "open",
                "assigned_support_user": ["oscar.perrin", "paula.morin", "samir.noel"][index % 3],
            }
        ],
        "shipments": [{"shipment_id": f"SHP-{suffix}-001", "order_id": f"ORD-{suffix}-001", "status": "ready"}],
        "replacements": [
            {
                "replacement_id": f"RPL-{suffix}-001",
                "old_serial": f"NB-CLIENT{suffix}-LAP-OLD",
                "new_serial": f"NB-CLIENT{suffix}-LAP-001",
                "status": "planned",
            }
        ],
    }


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def generate_files(root: Path) -> None:
    clients = root / "clients"
    clients.mkdir(parents=True, exist_ok=True)
    for index in range(1, 51):
        client_id = f"CLIENT-{index:03d}"
        base = clients / client_id
        payload = client_payload(client_id, index)
        write_json(base / "customer/company.json", payload["company"])
        write_json(base / "customer/contacts.json", payload["contacts"])
        write_json(base / "sales/prospect.json", payload["prospect"])
        write_json(base / "sales/account-owner.json", payload["account_owner"])
        write_json(base / "sales/signed-contracts.json", payload["signed_contracts"])
        write_json(base / "sales/orders.json", payload["orders"])
        write_json(base / "finance/invoices.json", payload["invoices"])
        write_json(base / "assets/hardware.json", payload["hardware"])
        write_json(base / "assets/serial-numbers.json", payload["serial_numbers"])
        write_json(base / "assets/licenses.json", payload["licenses"])
        write_json(base / "support/subscriptions.json", payload["subscriptions"])
        write_json(base / "support/tickets.json", payload["tickets"])
        write_json(base / "logistics/shipments.json", payload["shipments"])
        write_json(base / "logistics/replacements.json", payload["replacements"])


def apply_acl(root: Path, role_permissions: list[dict[str, str]]) -> None:
    run(["chown", "-R", "root:root", str(root)])
    run(["chmod", "-R", "o-rwx", str(root)])
    for group in ROLE_GROUPS.values():
        run(["setfacl", "-R", "-m", f"g:{group}:0", str(root)])
    for item in role_permissions:
        group = ROLE_GROUPS[item["role"]]
        mode = "rx" if item["permission"] == "read" else "rwx"
        for relative in RESOURCE_FILES[item["resource"]]:
            for path in sorted((root / "clients").glob(f"*/{relative}")):
                run(["setfacl", "-m", f"g:{group}:{mode}", str(path)])
                run(["setfacl", "-m", f"g:{group}:x", str(path.parent)])
                for parent in path.parents:
                    if parent == root.parent:
                        break
                    run(["setfacl", "-m", f"g:{group}:x", str(parent)])
    run(["setfacl", "-R", "-m", "g:crm-admin:rwx", str(root)])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    args = parser.parse_args()
    users = read_csv(args.policy / "users.csv")
    assignments = read_csv(args.policy / "golden-role-assignments.csv")
    role_permissions = read_csv(args.policy / "role-permissions.csv")
    for group in ROLE_GROUPS.values():
        ensure_group(group)
    for row in users:
        ensure_user(row)
    ensure_memberships(assignments)
    generate_files(args.root)
    apply_acl(args.root, role_permissions)


if __name__ == "__main__":
    main()
