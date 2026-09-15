from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
import json
import secrets
import sqlite3
from typing import Any

ROLES = {"ADMIN", "OPERATOR", "GROUP_OWNER", "BUSINESS_ADMIN"}

def init_system(conn: sqlite3.Connection) -> None:
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS system_users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL, role TEXT NOT NULL, scopes TEXT NOT NULL DEFAULT '[]', enabled INTEGER NOT NULL DEFAULT 1, password_hash TEXT, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS identity_provider_configs (id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, kind TEXT NOT NULL, endpoint TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 0, settings TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL);
    """)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(system_users)")}
    if "password_hash" not in columns:
        conn.execute("ALTER TABLE system_users ADD COLUMN password_hash TEXT")
    conn.commit()

def list_users(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return [{**dict(row), "scopes": json.loads(row["scopes"])} for row in conn.execute("SELECT id, username, display_name, role, scopes, enabled, created_at FROM system_users ORDER BY username")]

def _password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 240_000)
    return f"pbkdf2_sha256$240000${salt.hex()}${digest.hex()}"


def _password_matches(password: str, encoded: str | None) -> bool:
    if not encoded:
        return False
    try:
        algorithm, rounds_text, salt_hex, digest_hex = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds_text))
        return secrets.compare_digest(candidate.hex(), digest_hex)
    except (TypeError, ValueError):
        return False


def authenticate_user(conn: sqlite3.Connection, username: str, password: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT id, username, display_name, role, scopes, enabled, password_hash FROM system_users WHERE username = ?", (username.strip().lower(),)).fetchone()
    if row is None or not row["enabled"] or not _password_matches(password, row["password_hash"]):
        return None
    return {"subject": row["id"], "username": row["username"], "display_name": row["display_name"], "role": row["role"], "scopes": json.loads(row["scopes"])}


def ensure_bootstrap_user(conn: sqlite3.Connection) -> None:
    """Provision the first administrator only when explicit deployment secrets are supplied."""
    username = os.environ.get("EARE_ADMIN_USERNAME", "").strip()
    password = os.environ.get("EARE_ADMIN_PASSWORD")
    if not username or not password:
        return
    if conn.execute("SELECT 1 FROM system_users LIMIT 1").fetchone() is None:
        upsert_user(conn, {"username": username, "display_name": username, "role": "ADMIN", "password": password})


def upsert_user(conn: sqlite3.Connection, data: dict[str, Any]) -> dict[str, Any]:
    username = str(data.get("username", "")).strip().lower()
    role = str(data.get("role", "")).upper()
    scopes = sorted({str(x).strip() for x in data.get("scopes", []) if str(x).strip()})
    if not username or role not in ROLES:
        raise ValueError("username and supported role are required")
    if role == "ADMIN": scopes = ["*"]
    password = data.get("password")
    if password is not None and (not isinstance(password, str) or len(password) < 12):
        raise ValueError("password must contain at least 12 characters")
    record = {"id": username, "username": username, "display_name": str(data.get("display_name") or username), "role": role, "scopes": scopes, "enabled": bool(data.get("enabled", True)), "created_at": datetime.now(timezone.utc).isoformat()}
    password_hash = _password_hash(password) if isinstance(password, str) else None
    conn.execute("""INSERT INTO system_users(id, username, display_name, role, scopes, enabled, password_hash, created_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(username) DO UPDATE SET display_name=excluded.display_name, role=excluded.role, scopes=excluded.scopes, enabled=excluded.enabled, password_hash=COALESCE(excluded.password_hash, system_users.password_hash)""", (record["id"], record["username"], record["display_name"], record["role"], json.dumps(scopes), int(record["enabled"]), password_hash, record["created_at"]))
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
