from __future__ import annotations

import csv
import json
import shutil
import subprocess
from dataclasses import asdict
from pathlib import Path
from typing import Any

PROVIDER = "nexa-crm"
ROOT = Path(__file__).resolve().parents[1]
POLICY_DIR = ROOT / "policy"
ARTIFACTS_DIR = ROOT / "artifacts"
CONTAINER = "eare-crashtests-crm"

ROLE_GROUPS = {
    "CRM-Compta": "crm-compta",
    "CRM-Sales": "crm-sales",
    "CRM-Logistics": "crm-logistics",
    "CRM-Support": "crm-support",
    "CRM-Admin": "crm-admin",
}

RESOURCE_FILES = {
    "customer": "customer/company.json",
    "contacts": "customer/contacts.json",
    "prospects": "sales/prospect.json",
    "account_owner": "sales/account-owner.json",
    "contracts": "sales/signed-contracts.json",
    "orders": "sales/orders.json",
    "invoices": "finance/invoices.json",
    "hardware": "assets/hardware.json",
    "serial_numbers": "assets/serial-numbers.json",
    "licenses": "assets/licenses.json",
    "support": "support/subscriptions.json",
    "tickets": "support/tickets.json",
    "shipments": "logistics/shipments.json",
    "replacements": "logistics/replacements.json",
}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def role_permissions(policy_dir: Path = POLICY_DIR) -> list[dict[str, str]]:
    return read_csv(policy_dir / "role-permissions.csv")


def golden_assignments(policy_dir: Path = POLICY_DIR) -> list[dict[str, str]]:
    return read_csv(policy_dir / "golden-role-assignments.csv")


def users(policy_dir: Path = POLICY_DIR) -> list[dict[str, str]]:
    return read_csv(policy_dir / "users.csv")


def write_artifact(name: str, payload: Any) -> Path:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    path = ARTIFACTS_DIR / name
    if isinstance(payload, str):
        path.write_text(payload, encoding="utf-8")
    else:
        path.write_text(json.dumps(_jsonable(payload), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _jsonable(value: Any) -> Any:
    if hasattr(value, "__dataclass_fields__"):
        return asdict(value)
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    return value


def docker_available() -> tuple[bool, str]:
    if shutil.which("docker") is None:
        return False, "Docker CLI is not installed"
    version = subprocess.run(["docker", "version"], text=True, capture_output=True, check=False)
    if version.returncode != 0:
        return False, "Docker Engine is not reachable"
    inspect = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Status}}", CONTAINER],
        text=True,
        capture_output=True,
        check=False,
    )
    if inspect.returncode != 0 or inspect.stdout.strip() != "running":
        return False, "CrashTests-CRM container is not running; run tests/UAT/CrashTests-CRM/Run_CrashTests-CRM.sh"
    return True, ""


def docker_exec(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", "exec", CONTAINER, *args], text=True, capture_output=True, check=False)


def first_client_path(resource: str) -> str:
    return f"/srv/crm/clients/CLIENT-001/{RESOURCE_FILES[resource]}"


def assert_fs_case(user: str, resource: str, permission: str, allowed: bool) -> None:
    path = first_client_path(resource)
    if permission == "read":
        command = ["runuser", "-u", user, "--", "test", "-r", path]
    elif permission == "write":
        command = ["runuser", "-u", user, "--", "sh", "-c", f"test -w '{path}'"]
    else:
        raise ValueError(f"unsupported permission: {permission}")
    result = docker_exec(command)
    observed = result.returncode == 0
    if observed != allowed:
        write_artifact(
            "filesystem-access-failure.json",
            {
                "user": user,
                "resource": resource,
                "permission": permission,
                "expected_allowed": allowed,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            },
        )
    assert observed is allowed
