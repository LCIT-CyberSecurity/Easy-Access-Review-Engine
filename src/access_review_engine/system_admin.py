from __future__ import annotations

from datetime import datetime, timezone
import json
import sqlite3
import subprocess
from typing import Any

ROLES = {"ADMIN", "OPERATOR", "GROUP_OWNER", "BUSINESS_ADMIN"}

def init_system(conn: sqlite3.Connection) -> None:
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS system_users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL, role TEXT NOT NULL, scopes TEXT NOT NULL DEFAULT '[]', enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS identity_provider_configs (id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, kind TEXT NOT NULL, endpoint TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 0, settings TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL);
    """)
    conn.commit()

def list_users(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return [{**dict(row), "scopes": json.loads(row["scopes"])} for row in conn.execute("SELECT id, username, display_name, role, scopes, enabled, created_at FROM system_users ORDER BY username")]

def upsert_user(conn: sqlite3.Connection, data: dict[str, Any]) -> dict[str, Any]:
    username = str(data.get("username", "")).strip().lower()
    role = str(data.get("role", "")).upper()
    scopes = sorted({str(x).strip() for x in data.get("scopes", []) if str(x).strip()})
    if not username or role not in ROLES:
        raise ValueError("username and supported role are required")
    if role == "ADMIN": scopes = ["*"]
    record = {"id": username, "username": username, "display_name": str(data.get("display_name") or username), "role": role, "scopes": scopes, "enabled": bool(data.get("enabled", True)), "created_at": datetime.now(timezone.utc).isoformat()}
    conn.execute("""INSERT INTO system_users(id, username, display_name, role, scopes, enabled, created_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(username) DO UPDATE SET display_name=excluded.display_name, role=excluded.role, scopes=excluded.scopes, enabled=excluded.enabled""", (record["id"], record["username"], record["display_name"], record["role"], json.dumps(scopes), int(record["enabled"]), record["created_at"]))
    conn.commit()
    return record

def list_idps(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT id, name, kind, endpoint, enabled, settings, created_at FROM identity_provider_configs ORDER BY name")
    return [{**dict(row), "settings": json.loads(row["settings"])} for row in rows]

def upsert_idp(conn: sqlite3.Connection, data: dict[str, Any]) -> dict[str, Any]:
    name, kind, endpoint = str(data.get("name", "")).strip(), str(data.get("kind", "")).upper(), str(data.get("endpoint", "")).strip()
    if not name or kind not in {"LDAP", "OIDC", "SAML"} or not endpoint:
        raise ValueError("name, kind and endpoint are required")
    record = {"id": name.lower().replace(" ", "-"), "name": name, "kind": kind, "endpoint": endpoint, "enabled": bool(data.get("enabled", False)), "settings": data.get("settings", {}), "created_at": datetime.now(timezone.utc).isoformat()}
    conn.execute("""INSERT INTO identity_provider_configs(id,name,kind,endpoint,enabled,settings,created_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET kind=excluded.kind, endpoint=excluded.endpoint, enabled=excluded.enabled, settings=excluded.settings""", (record["id"], record["name"], record["kind"], record["endpoint"], int(record["enabled"]), json.dumps(record["settings"]), record["created_at"]))
    conn.commit()
    return record

def run_openldap_tests(root: str) -> dict[str, Any]:
    result = subprocess.run(["python3", "-m", "pytest", "tests/UAT/CrashTests-OpenLDAP/crashtests", "-q"], cwd=root, text=True, capture_output=True, timeout=120, check=False)
    return {"returncode": result.returncode, "stdout": result.stdout[-12000:], "stderr": result.stderr[-4000:]}
