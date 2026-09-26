from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import os
import json
import secrets
import sqlite3
from typing import Any, Callable

ROLES = {"ADMIN", "OPERATOR", "GROUP_OWNER", "BUSINESS_ADMIN", "REMEDIATION_MANAGER"}
LOCAL_SOURCE = "local"

def init_system(conn: sqlite3.Connection) -> None:
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS system_users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL, role TEXT NOT NULL, scopes TEXT NOT NULL DEFAULT '[]', enabled INTEGER NOT NULL DEFAULT 1, password_hash TEXT, must_change_password INTEGER NOT NULL DEFAULT 0, api_access_enabled INTEGER NOT NULL DEFAULT 0, session_version INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS identity_provider_configs (id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, kind TEXT NOT NULL, endpoint TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 0, settings TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS system_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS api_tokens (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_prefix TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, last_used_at TEXT, revoked_at TEXT);
    CREATE INDEX IF NOT EXISTS ix_api_tokens_user ON api_tokens(user_id);
    CREATE UNIQUE INDEX IF NOT EXISTS uq_api_tokens_one_active ON api_tokens(user_id) WHERE revoked_at IS NULL;
    """)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(system_users)")}
    if "password_hash" not in columns:
        conn.execute("ALTER TABLE system_users ADD COLUMN password_hash TEXT")
    if "must_change_password" not in columns:
        conn.execute("ALTER TABLE system_users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")
    if "auth_source" not in columns:
        conn.execute(f"ALTER TABLE system_users ADD COLUMN auth_source TEXT NOT NULL DEFAULT '{LOCAL_SOURCE}'")
    if "external_id" not in columns:
        conn.execute("ALTER TABLE system_users ADD COLUMN external_id TEXT")
    if "api_access_enabled" not in columns:
        conn.execute("ALTER TABLE system_users ADD COLUMN api_access_enabled INTEGER NOT NULL DEFAULT 0")
    if "session_version" not in columns:
        conn.execute("ALTER TABLE system_users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 1")
    conn.commit()

def list_users(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc).isoformat()
    rows = conn.execute("""SELECT u.id, u.username, u.display_name, u.role, u.scopes, u.enabled,
        u.must_change_password, u.api_access_enabled, u.session_version, u.auth_source, u.external_id, u.created_at,
        t.token_prefix, t.last_used_at
        FROM system_users u LEFT JOIN api_tokens t ON t.id = (
            SELECT id FROM api_tokens WHERE user_id = u.id AND revoked_at IS NULL AND expires_at > ?
            ORDER BY created_at DESC LIMIT 1
        ) ORDER BY u.username""", (now,))
    return [{
        **dict(row),
        "scopes": json.loads(row["scopes"]),
        "must_change_password": bool(row["must_change_password"]),
        "api_access_enabled": bool(row["api_access_enabled"]),
        "session_version": int(row["session_version"]),
        "api_token_active": row["token_prefix"] is not None,
        "api_token_prefix": row["token_prefix"],
        "api_token_last_used_at": row["last_used_at"],
    } for row in rows]

def external_user_api_enabled(conn: sqlite3.Connection) -> bool:
    row = conn.execute("SELECT value FROM system_settings WHERE key = ?", ("external_user_api_enabled",)).fetchone()
    return bool(row and row["value"] == "true")


def set_external_user_api_enabled(conn: sqlite3.Connection, enabled: bool) -> None:
    conn.execute(
        "INSERT INTO system_settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        ("external_user_api_enabled", "true" if enabled else "false"),
    )
    conn.commit()


def revoke_api_tokens(conn: sqlite3.Connection, user_id: str) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "UPDATE api_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
        (now, user_id),
    )
    conn.commit()
    return cursor.rowcount


def api_token_summary(conn: sqlite3.Connection, user_id: str) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    row = conn.execute(
        "SELECT token_prefix, created_at, expires_at, last_used_at FROM api_tokens "
        "WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ? ORDER BY created_at DESC LIMIT 1",
        (user_id, now),
    ).fetchone()
    if row is None:
        return {"active": False, "prefix": None, "created_at": None, "expires_at": None, "last_used_at": None}
    return {"active": True, "prefix": row["token_prefix"], "created_at": row["created_at"], "expires_at": row["expires_at"], "last_used_at": row["last_used_at"]}


def create_api_token(conn: sqlite3.Connection, user_id: str) -> dict[str, Any]:
    user = conn.execute("SELECT enabled, api_access_enabled FROM system_users WHERE id = ?", (user_id,)).fetchone()
    if user is None or not user["enabled"] or not user["api_access_enabled"]:
        raise ValueError("API access is not enabled for this account")
    token = "eare_pat_" + secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    created_at = now.isoformat()
    expires_at = (now + timedelta(days=90)).isoformat()
    token_id = secrets.token_hex(16)
    prefix = token[:16]
    conn.execute("UPDATE api_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL", (created_at, user_id))
    conn.execute(
        "INSERT INTO api_tokens(id, user_id, token_prefix, token_hash, created_at, expires_at) VALUES(?,?,?,?,?,?)",
        (token_id, user_id, prefix, hashlib.sha256(token.encode("utf-8")).hexdigest(), created_at, expires_at),
    )
    conn.commit()
    return {"token": token, "id": token_id, "prefix": prefix, "created_at": created_at, "expires_at": expires_at}


def authenticate_api_token(conn: sqlite3.Connection, token: str) -> dict[str, Any] | None:
    if not isinstance(token, str) or not token.startswith("eare_pat_") or len(token) > 128:
        return None
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    row = conn.execute("""SELECT t.id AS token_id, t.token_hash, t.token_prefix, t.expires_at, t.revoked_at,
        u.id, u.username, u.display_name, u.role, u.scopes, u.enabled, u.api_access_enabled,
        u.must_change_password
        FROM api_tokens t JOIN system_users u ON u.id = t.user_id WHERE t.token_hash = ?""", (digest,)).fetchone()
    if row is None or not secrets.compare_digest(str(row["token_hash"]), digest):
        return None
    if row["revoked_at"] is not None or not row["enabled"] or not row["api_access_enabled"]:
        return None
    try:
        if datetime.fromisoformat(str(row["expires_at"])) <= datetime.now(timezone.utc):
            return None
    except ValueError:
        return None
    if not external_user_api_enabled(conn):
        return None
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("UPDATE api_tokens SET last_used_at = ? WHERE id = ?", (now, row["token_id"]))
    conn.commit()
    return {
        "subject": str(row["id"]),
        "username": str(row["username"]),
        "display_name": str(row["display_name"]),
        "role": str(row["role"]),
        "scopes": json.loads(row["scopes"]),
        "must_change_password": bool(row["must_change_password"]),
        "token_id": str(row["token_id"]),
        "token_prefix": str(row["token_prefix"]),
    }


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


def authenticate_user(conn: sqlite3.Connection, username: str, password: str, directory: Callable[[str, str, str | None, str], bool] | None = None) -> dict[str, Any] | None:
    """Authenticate a local account against its hash, or a directory account against its directory.

    ``directory`` receives the directory name, the username, the stored external id and the
    password, and reports whether the directory accepted the credentials.
    """
    row = conn.execute("SELECT id, username, display_name, role, scopes, enabled, password_hash, must_change_password, session_version, auth_source, external_id FROM system_users WHERE username = ?", (username.strip().lower(),)).fetchone()
    if row is None or not row["enabled"]:
        return None
    source = row["auth_source"] or LOCAL_SOURCE
    if source == LOCAL_SOURCE:
        if not _password_matches(password, row["password_hash"]):
            return None
    elif directory is None or not directory(source, row["username"], row["external_id"], password):
        return None
    return {"subject": row["id"], "username": row["username"], "display_name": row["display_name"], "role": row["role"], "scopes": json.loads(row["scopes"]), "must_change_password": bool(row["must_change_password"]) and source == LOCAL_SOURCE, "session_version": int(row["session_version"]), "auth_source": source}


def ensure_bootstrap_user(conn: sqlite3.Connection) -> None:
    """Provision the first local administrator, with environment overrides."""
    if conn.execute("SELECT 1 FROM system_users LIMIT 1").fetchone() is None:
        username = os.environ.get("EARE_ADMIN_USERNAME", "admin").strip().lower() or "admin"
        password = os.environ.get("EARE_ADMIN_PASSWORD") or "admin"
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO system_users(id, username, display_name, role, scopes, enabled, password_hash, must_change_password, session_version, created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (username, username, username, "ADMIN", json.dumps(["*"]), 1, _password_hash(password), 1, 1, now),
        )
        conn.commit()


def upsert_user(conn: sqlite3.Connection, data: dict[str, Any]) -> dict[str, Any]:
    username = str(data.get("username", "")).strip().lower()
    role = str(data.get("role", "")).upper()
    scopes = sorted({str(x).strip() for x in data.get("scopes", []) if str(x).strip()})
    if not username or role not in ROLES:
        raise ValueError("username and supported role are required")
    if role == "ADMIN": scopes = ["*"]
    source = str(data.get("auth_source") or LOCAL_SOURCE).strip() or LOCAL_SOURCE
    external_id = str(data.get("external_id") or "").strip() or None
    existing = conn.execute("SELECT api_access_enabled FROM system_users WHERE username = ?", (username,)).fetchone()
    current_api_access = bool(existing["api_access_enabled"]) if existing is not None else False
    raw_api_access = data.get("api_access_enabled", current_api_access)
    if not isinstance(raw_api_access, bool):
        raise ValueError("api_access_enabled must be a boolean")
    api_access_enabled = raw_api_access
    password = data.get("password")
    if source != LOCAL_SOURCE and password:
        raise ValueError("directory accounts authenticate against their directory, not a stored password")
    if password is not None and (not isinstance(password, str) or len(password) < 12):
        raise ValueError("password must contain at least 12 characters")
    # An absent must_change_password keeps the stored flag: editing a user must not silently
    # clear a pending password change.
    must_change = data.get("must_change_password")
    must_change = None if must_change is None else int(bool(must_change) and source == LOCAL_SOURCE)
    record = {"id": username, "username": username, "display_name": str(data.get("display_name") or username), "role": role, "scopes": scopes, "enabled": bool(data.get("enabled", True)), "api_access_enabled": api_access_enabled, "auth_source": source, "external_id": external_id, "created_at": datetime.now(timezone.utc).isoformat()}
    password_hash = _password_hash(password) if isinstance(password, str) and source == LOCAL_SOURCE else None
    conn.execute("""INSERT INTO system_users(id, username, display_name, role, scopes, enabled, password_hash, must_change_password, api_access_enabled, auth_source, external_id, created_at)
        VALUES(?,?,?,?,?,?,?,COALESCE(?,0),?,?,?,?)
        ON CONFLICT(username) DO UPDATE SET display_name=excluded.display_name, role=excluded.role, scopes=excluded.scopes,
        enabled=excluded.enabled, api_access_enabled=excluded.api_access_enabled,
        password_hash=CASE WHEN excluded.auth_source <> ? THEN NULL ELSE COALESCE(excluded.password_hash, system_users.password_hash) END,
        must_change_password=COALESCE(?, system_users.must_change_password), auth_source=excluded.auth_source,
        external_id=COALESCE(excluded.external_id, system_users.external_id),
        session_version=system_users.session_version + CASE WHEN excluded.auth_source <> system_users.auth_source THEN 1 ELSE 0 END""",
        (record["id"], record["username"], record["display_name"], record["role"], json.dumps(scopes),
         int(record["enabled"]), password_hash, must_change, int(api_access_enabled), source, external_id,
         record["created_at"], LOCAL_SOURCE, must_change))
    conn.commit()
    record["must_change_password"] = bool(conn.execute("SELECT must_change_password FROM system_users WHERE username = ?", (username,)).fetchone()[0])
    if not api_access_enabled:
        revoke_api_tokens(conn, username)
    return record

def set_enabled(conn: sqlite3.Connection, username: str, enabled: bool) -> dict[str, Any]:
    """Suspend or restore an account without losing its history."""
    normalized = username.strip().lower()
    if conn.execute("SELECT 1 FROM system_users WHERE username = ?", (normalized,)).fetchone() is None:
        raise ValueError("user not found")
    conn.execute("UPDATE system_users SET enabled = ? WHERE username = ?", (int(bool(enabled)), normalized))
    conn.commit()
    if not enabled:
        revoke_api_tokens(conn, normalized)
    return {"username": normalized, "enabled": bool(enabled)}

def reset_password(conn: sqlite3.Connection, username: str, password: str) -> dict[str, Any]:
    """Set a local account password on behalf of its owner, who must then change it."""
    normalized = username.strip().lower()
    row = conn.execute("SELECT auth_source FROM system_users WHERE username = ?", (normalized,)).fetchone()
    if row is None:
        raise ValueError("user not found")
    if (row["auth_source"] or LOCAL_SOURCE) != LOCAL_SOURCE:
        raise ValueError("directory accounts change their password in their directory")
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError("password must contain at least 12 characters")
    conn.execute("UPDATE system_users SET password_hash = ?, must_change_password = 1, session_version = session_version + 1 WHERE username = ?", (_password_hash(password), normalized))
    conn.commit()
    return {"username": normalized, "must_change_password": True}

def enabled_admins(conn: sqlite3.Connection, excluding: str | None = None) -> int:
    """Count the administrators who could still sign in, to keep at least one."""
    rows = conn.execute("SELECT username FROM system_users WHERE role = 'ADMIN' AND enabled = 1")
    return sum(1 for row in rows if row["username"] != (excluding or "").strip().lower())

def change_password(conn: sqlite3.Connection, username: str, password: str) -> dict[str, Any]:
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError("password must contain at least 12 characters")
    normalized = username.strip().lower()
    if conn.execute("SELECT 1 FROM system_users WHERE username = ?", (normalized,)).fetchone() is None:
        raise ValueError("user not found")
    conn.execute("UPDATE system_users SET password_hash = ?, must_change_password = 0, session_version = session_version + 1 WHERE username = ?", (_password_hash(password), normalized))
    conn.commit()
    return authenticate_user(conn, normalized, password) or {}

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
