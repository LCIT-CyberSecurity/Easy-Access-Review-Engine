from __future__ import annotations

from dataclasses import asdict, dataclass
import base64
import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
import tempfile
import time
import yaml
from pathlib import Path
from typing import Any

try:
    from fastapi import Body, FastAPI, HTTPException, Request, Response
    from fastapi.responses import StreamingResponse
except ModuleNotFoundError:  # pragma: no cover
    FastAPI = None  # type: ignore[assignment]
    Body = Request = Response = HTTPException = StreamingResponse = None  # type: ignore[assignment,misc]

from access_review_engine.application import import_file_to_repository
from access_review_engine.authentication import compare_authentication_posture
from access_review_engine.collector_runner import RunnerError, run_exporter
from access_review_engine.config_loader import connector_path, load_connector, secret_environment, validate_connector
from access_review_engine.reporting import build_report_rows, report_summary, write_reports
from access_review_engine.services import audit, calculate_effective_accesses, close_campaign, create_decision, create_golden_source, create_golden_version, golden_diff, golden_version_from_snapshot, open_campaign, promote_campaign, promote_snapshot, remediation_from_decisions
from access_review_engine.storage import Repository, hydrate_authentication_posture, hydrate_campaign, hydrate_decision, hydrate_golden_source, hydrate_golden_version, hydrate_review_item, hydrate_snapshot
from access_review_engine.web_jobs import create_job, get_events, get_job, update_progress
from access_review_engine.web_read_models import projected_rows
from access_review_engine.web_use_cases import latest_snapshot, list_payloads, prepare_campaign_review, preview_campaign_review, preview_import
from access_review_engine.directory_auth import DirectoryError, authenticate as directory_authenticate, search_accounts as directory_accounts, test_directory, validate_directory
from access_review_engine.system_admin import LOCAL_SOURCE, authenticate_user, change_password as update_password, enabled_admins, ensure_bootstrap_user, init_system, list_idps, list_users, reset_password, set_enabled, upsert_idp, upsert_user


SESSION_COOKIE = "eare_session"
SESSION_TTL_SECONDS = 8 * 60 * 60
ROLES = ("ADMIN", "OPERATOR", "GROUP_OWNER", "BUSINESS_ADMIN")


@dataclass(frozen=True)
class WebPrincipal:
    subject: str
    role: str
    scopes: frozenset[str]
    username: str = ""
    display_name: str = ""
    must_change_password: bool = False

    def can_access(self, scope: str | None) -> bool:
        return self.role == "ADMIN" or not scope or "*" in self.scopes or scope in self.scopes


def _encode_session(principal: dict[str, Any], secret: bytes) -> str:
    payload = {"sub": principal["subject"], "username": principal["username"], "display_name": principal["display_name"], "role": principal["role"], "scopes": principal["scopes"], "must_change_password": bool(principal.get("must_change_password", False)), "exp": int(time.time()) + SESSION_TTL_SECONDS}
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    signature = hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{signature}"


def _decode_session(token: str | None, secret: bytes) -> WebPrincipal | None:
    if not token or "." not in token:
        return None
    body, signature = token.rsplit(".", 1)
    expected = hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return None
    try:
        padded = body + "=" * (-len(body) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        if int(payload["exp"]) < int(time.time()) or payload["role"] not in ROLES:
            return None
        return WebPrincipal(str(payload["sub"]), str(payload["role"]), frozenset(str(item) for item in payload.get("scopes", [])), str(payload.get("username", "")), str(payload.get("display_name", "")), bool(payload.get("must_change_password", False)))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def _require(user: WebPrincipal | None, roles: tuple[str, ...] = (), scope: str | None = None) -> WebPrincipal:
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    if user.must_change_password:
        raise HTTPException(status_code=403, detail="Password change required")
    if roles and user.role not in roles and user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Insufficient role")
    if not user.can_access(scope):
        raise HTTPException(status_code=403, detail="Scope is not authorized")
    return user


def create_app(db_path: str | None = None):
    if FastAPI is None:
        raise RuntimeError("Install the 'app' extra to use the REST API")
    db_path = db_path or os.environ.get("EARE_DB_PATH", "access-review.db")
    app = FastAPI(title="Easy Access Review Engine", version="0.3.0")
    system_conn = sqlite3.connect(db_path, check_same_thread=False)
    system_conn.row_factory = sqlite3.Row
    init_system(system_conn)
    ensure_bootstrap_user(system_conn)
    session_secret = os.environ.get("EARE_SESSION_SECRET", "").encode() or secrets.token_bytes(32)
    connector_directory = Path(db_path).resolve().parent / "connectors"

    def _load_web_connector(provider: str) -> dict[str, Any]:
        try:
            return load_connector(provider, connector_path(provider, connector_directory))
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    def _validate_web_connector(payload: dict[str, Any]) -> dict[str, Any]:
        candidate = dict(payload)
        provider = str(candidate.get("provider", "")).strip().lower()
        candidate["provider"] = provider
        try:
            validate_connector(candidate, provider)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        candidate.pop("_path", None)
        return candidate

    def _public_connector(payload: dict[str, Any]) -> dict[str, Any]:
        result = dict(payload)
        result.pop("_path", None)
        credentials = result.get("credentials")
        if isinstance(credentials, dict):
            result["credentials"] = {key: value for key, value in credentials.items() if key.endswith("_env")}
        return result

    def current_user(request: Request) -> WebPrincipal | None:
        """Decode the session, then confirm the account is still allowed what it claims.

        The cookie is self-contained, so a disabled account or a changed role would otherwise
        keep its previous rights until the cookie expires.
        """
        principal = _decode_session(request.cookies.get(SESSION_COOKIE), session_secret)
        if principal is None:
            return None
        stored = next((item for item in list_users(system_conn) if item.get("username") == principal.username), None)
        if stored is None or not stored.get("enabled"):
            return None
        return WebPrincipal(
            principal.subject,
            str(stored.get("role", principal.role)),
            frozenset(str(scope) for scope in stored.get("scopes", [])),
            principal.username,
            str(stored.get("display_name", principal.display_name)),
            bool(stored.get("must_change_password", False)),
        )

    def _directory_config(name: str, *, require_enabled: bool = True) -> dict[str, Any] | None:
        config = next((item for item in list_idps(system_conn) if item.get("name") == name), None)
        if config is None or (require_enabled and not config.get("enabled")):
            return None
        return config

    def _directory_login(source: str, username: str, external_id: str | None, password: str) -> bool:
        """Verify a directory account against its directory at sign-in time."""
        config = _directory_config(source)
        if config is None:
            return False
        try:
            return directory_authenticate(config, username, password, distinguished_name=external_id) is not None
        except DirectoryError:
            return False

    def _stored_user(username: str) -> dict[str, Any] | None:
        return next((item for item in list_users(system_conn) if item.get("username") == str(username).strip().lower()), None)

    def record_audit(
        repo: Repository,
        request: Request,
        event_type: str,
        object_type: str | None = None,
        object_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        principal = current_user(request)
        event = audit(event_type, object_type, object_id)
        event.actor = principal.subject if principal else None
        event.details = details or {}
        repo.insert_append_only("audit_events", event)

    def record_sign_in_event(event_type: str, actor: str, details: dict[str, Any] | None = None) -> None:
        """Sign-in events name their own actor: there is no session to read them from yet."""
        event = audit(event_type, "user", actor)
        event.actor = actor
        event.details = details or {}
        with Repository(db_path) as repo:
            repo.insert_append_only("audit_events", event)

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    def page(table: str, limit: int, offset: int, search: str | None, status: str | None, provider: str | None, campaign: str | None = None, sort: str | None = None, order: str | None = None):
        return projected_rows(db_path, table, limit=max(1, min(limit, 500)), offset=max(0, offset), search=search, status=status, provider=provider, campaign=campaign, sort=sort, order=order)

    def scoped_page(principal: WebPrincipal, table: str, limit: int, offset: int, search: str | None, status: str | None, provider: str | None, campaign: str | None = None, sort: str | None = None, order: str | None = None):
        return projected_rows(db_path, table, limit=max(1, min(limit, 500)), offset=max(0, offset), search=search, status=status, provider=provider, campaign=campaign, sort=sort, order=order, reviewer_username=principal.username if principal.role == "GROUP_OWNER" else None, allowed_providers=principal.scopes if principal.role == "BUSINESS_ADMIN" else None)

    def require_table_access(principal: WebPrincipal, table: str) -> None:
        if principal.role == "BUSINESS_ADMIN" and table != "remediation_actions":
            raise HTTPException(status_code=403, detail="This role can only access remediation actions")
        if principal.role == "GROUP_OWNER" and table != "review_items":
            raise HTTPException(status_code=403, detail="This role can only access assigned reviews")

    @app.post("/api/auth/login")
    def login(payload: dict[str, Any] = Body(...), response: Response = None):  # type: ignore[assignment]
        username, password = payload.get("username"), payload.get("password")
        if not isinstance(username, str) or not isinstance(password, str) or not username.strip() or not password:
            raise HTTPException(status_code=400, detail="Username and password are required")
        principal = authenticate_user(system_conn, username, password, _directory_login)
        if principal is None:
            record_sign_in_event("auth.sign_in_failed", username.strip().lower())
            raise HTTPException(status_code=401, detail="Invalid credentials")
        record_sign_in_event("auth.signed_in", principal["username"], {"role": principal["role"], "auth_source": principal.get("auth_source", LOCAL_SOURCE)})
        response.set_cookie(SESSION_COOKIE, _encode_session(principal, session_secret), httponly=True, secure=os.environ.get("EARE_COOKIE_SECURE") == "1", samesite="strict", max_age=SESSION_TTL_SECONDS, path="/")
        return {"subject": principal["subject"], "username": principal["username"], "display_name": principal["display_name"], "role": principal["role"], "scopes": principal["scopes"], "must_change_password": bool(principal.get("must_change_password", False))}

    @app.post("/api/auth/change-password")
    def change_password(request: Request, payload: dict[str, Any] = Body(...), response: Response = None):  # type: ignore[assignment]
        principal = current_user(request)
        if principal is None:
            raise HTTPException(status_code=401, detail="Authentication required")
        password = payload.get("new_password")
        stored = _stored_user(principal.username)
        if stored is not None and (stored.get("auth_source") or LOCAL_SOURCE) != LOCAL_SOURCE:
            raise HTTPException(status_code=400, detail="Directory accounts change their password in their directory")
        try:
            updated = update_password(system_conn, principal.username, password)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        record_sign_in_event("auth.password_changed", str(updated["username"]))
        response.set_cookie(SESSION_COOKIE, _encode_session(updated, session_secret), httponly=True, secure=os.environ.get("EARE_COOKIE_SECURE") == "1", samesite="strict", max_age=SESSION_TTL_SECONDS, path="/")
        return {"subject": updated["subject"], "username": updated["username"], "display_name": updated["display_name"], "role": updated["role"], "scopes": updated["scopes"], "must_change_password": False}

    @app.post("/api/auth/logout")
    def logout(request: Request, response: Response):
        principal = current_user(request)
        if principal is not None:
            record_sign_in_event("auth.signed_out", principal.username)
        response.delete_cookie(SESSION_COOKIE, path="/")
        return {"ok": True}

    @app.get("/api/auth/session")
    def session(request: Request):
        principal = current_user(request)
        if principal is None:
            raise HTTPException(status_code=401, detail="Authentication required")
        return asdict(principal)

    @app.get("/api/me")
    def me(request: Request):
        return asdict(_require(current_user(request)))

    def _pending_reviews_by_reviewer() -> dict[str, int]:
        """Count the reviews still waiting on each reviewer, in open campaigns only."""
        counts: dict[str, int] = {}
        with Repository(db_path) as repo:
            open_campaigns = {str(row.get("id")) for row in repo.list_payloads("campaigns") if row.get("status") == "open"}
            decided = {str(row.get("review_item_id")) for row in repo.list_payloads("decisions")}
            for row in repo.list_payloads("review_items"):
                identity = str((row.get("reviewer") or {}).get("identity", "")).lower()
                if identity and str(row.get("campaign_id")) in open_campaigns and str(row.get("id")) not in decided:
                    counts[identity] = counts.get(identity, 0) + 1
        return counts

    @app.get("/api/system")
    def system_overview(request: Request):
        _require(current_user(request), ("ADMIN",))
        pending = _pending_reviews_by_reviewer()
        users = [{**user, "pending_reviews": pending.get(str(user.get("username", "")).lower(), 0)} for user in list_users(system_conn)]
        return {"users": users, "identity_providers": list_idps(system_conn), "roles": sorted(ROLES)}

    @app.post("/api/system/users/{username}/reassign-reviews")
    def system_user_reassign_reviews(username: str, request: Request, payload: dict[str, Any] = Body(...)):
        """Hand the pending reviews of one person to another, so a leaver cannot block a campaign."""
        from access_review_engine.domain import OwnerRef

        _require(current_user(request), ("ADMIN",))
        origin = str(username).strip().lower()
        target = str(payload.get("to", "")).strip().lower()
        stored_target = _stored_user(target)
        if not target or stored_target is None or not stored_target.get("enabled"):
            raise HTTPException(status_code=400, detail="Choose an enabled EARE user to take the reviews over")
        if target == origin:
            raise HTTPException(status_code=400, detail="Choose a different user")
        moved = 0
        with Repository(db_path) as repo:
            open_campaigns = {str(row.get("id")) for row in repo.list_payloads("campaigns") if row.get("status") == "open"}
            decided = {str(row.get("review_item_id")) for row in repo.list_payloads("decisions")}
            for row in repo.list_payloads("review_items"):
                reviewer = row.get("reviewer") or {}
                if str(reviewer.get("identity", "")).lower() != origin:
                    continue
                # Decided items keep their reviewer: they are evidence of who decided what.
                if str(row.get("id")) in decided or str(row.get("campaign_id")) not in open_campaigns:
                    continue
                item = hydrate_review_item(row)
                item.reviewer = OwnerRef(provider=str(reviewer.get("provider") or item.identity_provider), identity=target)
                repo.upsert("review_items", item)
                moved += 1
            record_audit(repo, request, "review.reassigned", "user", origin, {"to": target, "review_items": moved})
        return {"from": origin, "to": target, "review_items": moved}

    def _guard_admin_access(principal: WebPrincipal, username: str, *, role: str | None = None, enabled: bool = True) -> None:
        """Refuse a change that would lock the administrator, or EARE itself, out."""
        target = str(username).strip().lower()
        stored = _stored_user(target)
        if stored is None:
            return
        losing_admin = str(stored.get("role")) == "ADMIN" and (not enabled or (role is not None and role != "ADMIN"))
        if not losing_admin:
            return
        if target == principal.username:
            raise HTTPException(status_code=409, detail="You cannot remove your own administrator access. Ask another administrator.")
        if enabled_admins(system_conn, excluding=target) == 0:
            raise HTTPException(status_code=409, detail="This is the last administrator who can sign in. Give another user the ADMIN role first.")

    @app.post("/api/system/users")
    def system_user_create(request: Request, payload: dict[str, Any] = Body(...)):
        principal = _require(current_user(request), ("ADMIN",))
        source = str(payload.get("auth_source") or LOCAL_SOURCE).strip() or LOCAL_SOURCE
        if source != LOCAL_SOURCE and _directory_config(source) is None:
            raise HTTPException(status_code=400, detail="This directory is not configured or not enabled")
        _guard_admin_access(principal, payload.get("username", ""), role=str(payload.get("role", "")).upper() or None, enabled=bool(payload.get("enabled", True)))
        try:
            result = upsert_user(system_conn, payload)
            with Repository(db_path) as repo:
                record_audit(repo, request, "system.user_upserted", "user", str(result.get("username", "")), {"role": result.get("role", ""), "auth_source": result.get("auth_source", LOCAL_SOURCE)})
            return result
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/system/users/{username}/disable")
    def system_user_disable(username: str, request: Request):
        principal = _require(current_user(request), ("ADMIN",))
        _guard_admin_access(principal, username, enabled=False)
        try:
            result = set_enabled(system_conn, username, False)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        with Repository(db_path) as repo:
            record_audit(repo, request, "system.user_disabled", "user", result["username"])
        return result

    @app.post("/api/system/users/{username}/enable")
    def system_user_enable(username: str, request: Request):
        _require(current_user(request), ("ADMIN",))
        try:
            result = set_enabled(system_conn, username, True)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        with Repository(db_path) as repo:
            record_audit(repo, request, "system.user_enabled", "user", result["username"])
        return result

    @app.post("/api/system/users/{username}/reset-password")
    def system_user_reset_password(username: str, request: Request, payload: dict[str, Any] = Body(...)):
        _require(current_user(request), ("ADMIN",))
        try:
            result = reset_password(system_conn, username, payload.get("password"))
        except ValueError as exc:
            status = 404 if str(exc) == "user not found" else 400
            raise HTTPException(status_code=status, detail=str(exc)) from exc
        with Repository(db_path) as repo:
            record_audit(repo, request, "system.user_password_reset", "user", result["username"])
        return result

    def _validated_idp(payload: dict[str, Any]) -> dict[str, Any]:
        candidate = {**payload, "name": str(payload.get("name", "")).strip(), "kind": str(payload.get("kind", "")).upper()}
        if candidate["kind"] == "LDAP":
            try:
                validate_directory(candidate)
            except DirectoryError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        return candidate

    @app.post("/api/system/identity-providers")
    def system_idp_create(request: Request, payload: dict[str, Any] = Body(...)):
        _require(current_user(request), ("ADMIN",))
        try:
            result = upsert_idp(system_conn, _validated_idp(payload))
            with Repository(db_path) as repo:
                record_audit(repo, request, "system.identity_provider_upserted", "identity_provider", str(result.get("name", "")), {"kind": result.get("kind", ""), "enabled": result.get("enabled", False)})
            return result
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/system/identity-providers/test")
    def system_idp_test(request: Request, payload: dict[str, Any] = Body(...)):
        """Check a directory configuration before it is saved."""
        _require(current_user(request), ("ADMIN",))
        try:
            return test_directory(_validated_idp(payload))
        except DirectoryError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    @app.get("/api/system/identity-providers/{name}/accounts")
    def system_idp_accounts(name: str, request: Request, search: str = "", limit: int = 25):
        """List directory accounts an administrator can import as EARE users."""
        _require(current_user(request), ("ADMIN",))
        config = _directory_config(name, require_enabled=False)
        if config is None:
            raise HTTPException(status_code=404, detail="Directory not found")
        try:
            accounts = directory_accounts(config, search, limit)
        except DirectoryError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        known = {str(user.get("username")) for user in list_users(system_conn)}
        return {"items": [{**account, "imported": account["login"].lower() in known} for account in accounts], "directory": name}

    @app.get("/api/system/sources")
    def system_sources(request: Request):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        connector_directory.mkdir(parents=True, exist_ok=True)
        sources = []
        for path in sorted(connector_directory.glob("*.yaml")):
            try:
                sources.append(_public_connector(load_connector(path.stem, path)))
            except ValueError:
                continue
        return {"sources": sources}

    @app.post("/api/system/sources")
    def system_source_save(request: Request, payload: dict[str, Any] = Body(...)):
        _require(current_user(request), ("ADMIN",))
        candidate = _validate_web_connector(payload)
        path = connector_path(str(candidate["provider"]), connector_directory)
        connector_directory.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(candidate, sort_keys=False), encoding="utf-8")
        with Repository(db_path) as repo:
            record_audit(repo, request, "source.configuration_saved", "provider", str(candidate["provider"]), {"type": candidate["type"]})
        return _public_connector(load_connector(str(candidate["provider"]), path))

    @app.post("/api/system/sources/test")
    def system_source_test(request: Request, payload: dict[str, Any] = Body(...)):
        _require(current_user(request), ("ADMIN",))
        candidate = _validate_web_connector(payload)
        try:
            secret_environment(candidate)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        candidate["_check_only"] = True
        with tempfile.TemporaryDirectory(prefix="eare-source-check-") as directory:
            output = Path(directory) / "connection-check.zip"
            try:
                result = run_exporter(candidate, output)
            except (RunnerError, ValueError) as exc:
                raise HTTPException(status_code=502, detail="Source connection test failed") from exc
        if result.returncode:
            raise HTTPException(status_code=502, detail="Source connection test failed")
        return {"status": "healthy", "provider": candidate["provider"], "message": "Connection test succeeded"}

    @app.post("/api/golden-sources/baseline")
    def create_baseline(request: Request, payload: dict[str, Any] | None = Body(default=None)):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            snapshots = repo.list_payloads("snapshots")
            if not snapshots:
                raise HTTPException(status_code=409, detail="No snapshot is available to create a baseline")
            requested = payload or {}
            snapshot_id = requested.get("snapshot_id")
            selected = next((row for row in snapshots if row.get("id") == snapshot_id), None) if snapshot_id else snapshots[-1]
            if selected is None:
                raise HTTPException(status_code=404, detail="Requested snapshot not found")
            snapshot = hydrate_snapshot(selected)
            name = str(requested.get("name") or "").strip()
            if not name:
                raise HTTPException(status_code=400, detail="Golden Source name is required")
            display_name = str(requested.get("display_name") or name).strip()
            existing = repo.find_by_name("golden_sources", name)
            source = hydrate_golden_source(existing) if existing else create_golden_source(name, display_name)
            previous = [hydrate_golden_version(row) for row in repo.list_payloads("golden_source_versions") if row.get("golden_source_id") == source.id]
            try:
                version = promote_snapshot(source, snapshot, previous)
            except ValueError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            source.active_version_id = version.id
            repo.upsert("golden_sources", source)
            repo.upsert("golden_source_versions", version)
            record_audit(repo, request, "golden_source.version_created", "golden_source_version", version.id, {"source_id": source.id, "version": version.version})
            return {"source": asdict(source), "version": asdict(version), "snapshot_id": snapshot.id}

    @app.get("/api/golden-sources/{name}/compare")
    def compare_baseline(name: str, request: Request):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            source_payload = repo.find_by_name("golden_sources", name)
            if not source_payload:
                raise HTTPException(status_code=404, detail="Golden Source not found")
            source = hydrate_golden_source(source_payload)
            versions = [hydrate_golden_version(row) for row in repo.list_payloads("golden_source_versions") if row.get("golden_source_id") == source.id]
            if not versions:
                raise HTTPException(status_code=409, detail="Golden Source has no version to compare")
            snapshot = hydrate_snapshot(repo.list_payloads("snapshots")[-1]) if repo.list_payloads("snapshots") else None
            if snapshot is None:
                raise HTTPException(status_code=409, detail="A snapshot is required for comparison")
            try:
                current = golden_version_from_snapshot(source, snapshot, versions)
            except ValueError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            active = max(versions, key=lambda item: item.version)
            return {"name": name, "active_version": active.version, "active_golden_version_id": active.id, "observed_snapshot_id": snapshot.id, "changes": golden_diff(active, current)}


    @app.post("/api/golden-sources/{name}/confirm-version")
    def confirm_golden_version(name: str, request: Request, payload: dict[str, Any] = Body(...)):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        snapshot_id = payload.get("observed_snapshot_id")
        expected_id = payload.get("active_golden_version_id")
        if not isinstance(snapshot_id, str) or not isinstance(expected_id, str):
            raise HTTPException(status_code=400, detail="Comparison context is required")
        with Repository(db_path) as repo:
            source_payload = repo.find_by_name("golden_sources", name)
            if not source_payload:
                raise HTTPException(status_code=404, detail="Golden Source not found")
            source = hydrate_golden_source(source_payload)
            versions = [hydrate_golden_version(row) for row in repo.list_payloads("golden_source_versions") if row.get("golden_source_id") == source.id]
            active = max(versions, key=lambda item: item.version) if versions else None
            snapshots = repo.list_payloads("snapshots")
            current_snapshot = snapshots[-1] if snapshots else None
            if current_snapshot is None or current_snapshot.get("id") != snapshot_id or active is None or active.id != expected_id:
                raise HTTPException(status_code=409, detail="The observed or expected data changed since this comparison. Please compare again before confirming.")
            snapshot = hydrate_snapshot(current_snapshot)
            try:
                version = promote_snapshot(source, snapshot, versions)
            except ValueError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            source.active_version_id = version.id
            repo.upsert("golden_sources", source)
            repo.upsert("golden_source_versions", version)
            record_audit(repo, request, "golden_source.version_confirmed", "golden_source_version", version.id, {"source_id": source.id, "version": version.version, "snapshot_id": snapshot_id})
            return {"source": asdict(source), "version": asdict(version), "observed_snapshot_id": snapshot_id, "active_golden_version_id": expected_id}
    def _golden_context(repo: Repository, name: str):
        """Return the Golden Source, its versions and the active one."""
        payload = repo.find_by_name("golden_sources", name)
        if not payload:
            raise HTTPException(status_code=404, detail="Golden Source not found")
        source = hydrate_golden_source(payload)
        versions = [hydrate_golden_version(row) for row in repo.list_payloads("golden_source_versions") if row.get("golden_source_id") == source.id]
        active = next((item for item in versions if item.id == source.active_version_id), None) or (max(versions, key=lambda item: item.version) if versions else None)
        return source, versions, active

    @app.get("/api/golden-sources/{name}/assignments")
    def golden_assignments(name: str, request: Request, search: str | None = None, limit: int = 25, offset: int = 0, sort: str | None = None, order: str | None = None):
        """Read what the Golden Source currently expects, so it can be reviewed in the WebUI."""
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            source, versions, active = _golden_context(repo, name)
            if active is None:
                raise HTTPException(status_code=409, detail="Golden Source has no version yet")
            from access_review_engine.web_read_models import _display_names

            identity_names, access_names = _display_names(repo)
            # What an expected access actually is stays on the Access object, collected once.
            catalog = {(str(row.get("provider")), str(row.get("name"))): row for row in repo.list_payloads("accesses")}
            rows = []
            for item in sorted(active.assignments, key=lambda entry: entry.key()):
                row = asdict(item)
                # Show the names people recognise; collectors key objects by their native id.
                row["identity_display_name"] = identity_names.get((item.identity_provider, item.identity_identifier)) or item.identity_identifier
                row["access_display_name"] = access_names.get((item.access_provider, item.access_name)) or item.access_name
                described = catalog.get((item.access_provider, item.access_name), {})
                row["access_description"] = described.get("description")
                row["access_target"] = described.get("target")
                row["access_owner"] = described.get("access_owner")
                if not row.get("access_permission"):
                    permission = described.get("permission")
                    row["access_permission"] = (permission or {}).get("display_name") or (permission or {}).get("identifier") if isinstance(permission, dict) else permission
                rows.append(row)
            covered = sorted({str(item.access_provider) for item in active.assignments})
            campaign_name = next((str(row.get("name")) for row in repo.list_payloads("campaigns") if str(row.get("id")) == str(active.source_campaign_id)), None)
            snapshots = repo.list_payloads("snapshots")
            collected = [str(item.get("name")) for item in (snapshots[-1].get("providers", []) if snapshots else [])]
            if search:
                needle = search.casefold()
                rows = [row for row in rows if needle in " ".join(str(value or "") for value in row.values()).casefold()]
            if sort:
                from access_review_engine.web_read_models import sorted_rows

                rows = sorted_rows(rows, sort, order)
            bounded = max(1, min(limit, 500))
            start = max(0, offset)
            return {
                "items": rows[start : start + bounded],
                "total": len(rows),
                "limit": bounded,
                "offset": start,
                "sort": sort or "",
                "order": (order or "asc").lower(),
                "version": active.version,
                "version_id": active.id,
                "source_type": active.source_type,
                "created_at": active.created_at,
                "created_by": active.created_by,
                "source_snapshot_id": active.source_snapshot_id,
                "source_campaign_id": active.source_campaign_id,
                "source_campaign_name": campaign_name,
                "comment": active.comment,
                "providers": covered,
                "collected_providers": collected,
                "collected_at": snapshots[-1].get("created_at") if snapshots else None,
                "versions": [{"id": item.id, "version": item.version, "source_type": item.source_type, "created_at": item.created_at, "assignments": len(item.assignments), "comment": item.comment} for item in sorted(versions, key=lambda item: item.version)],
            }

    @app.get("/api/golden-sources/{name}/authentication")
    def golden_authentication(name: str, request: Request):
        """Expected authentication controls against the ones the collection observed."""
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            source, versions, active = _golden_context(repo, name)
            snapshots = repo.list_payloads("snapshots")
            covered = sorted({str(item.access_provider) for item in active.assignments}) if active else []
            # Read the posture of a collection that covers what this expected state describes.
            relevant = [row for row in snapshots if not covered or {str(item.get("name")) for item in row.get("providers", [])} & set(covered)]
            observed_payload = next((row.get("authentication_posture") for row in reversed(relevant) if row.get("authentication_posture")), None)
            collected_at = next((row.get("created_at") for row in reversed(relevant) if row.get("authentication_posture")), None)
        expected = active.golden_authentication_policy if active else None
        observed = hydrate_authentication_posture(observed_payload) if observed_payload else None
        rows = compare_authentication_posture(expected, observed)
        return {
            "version": active.version if active else None,
            "expected": asdict(expected) if expected else None,
            "observed": asdict(observed) if observed else None,
            "collected_at": collected_at,
            "providers": covered,
            "controls": rows,
            "summary": {
                "compliant": sum(1 for row in rows if row["assessment"] == "compliant"),
                "deviation": sum(1 for row in rows if row["assessment"] == "deviation"),
                "unknown": sum(1 for row in rows if row["assessment"] in {"unknown", "not_collected"}),
            },
        }

    @app.post("/api/golden-sources/{name}/authentication")
    def golden_adopt_authentication(name: str, request: Request, payload: dict[str, Any] | None = Body(default=None)):
        """Record the observed authentication posture as the expected one, in a new version."""
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            source, versions, active = _golden_context(repo, name)
            if active is None:
                raise HTTPException(status_code=409, detail="Golden Source has no version yet")
            snapshots = repo.list_payloads("snapshots")
            observed_payload = next((row.get("authentication_posture") for row in reversed(snapshots) if row.get("authentication_posture")), None)
            if observed_payload is None:
                raise HTTPException(status_code=409, detail="No collection has reported an authentication posture yet")
            posture = hydrate_authentication_posture(observed_payload)
            version = create_golden_version(source, set(active.assignments), "manual", versions, parent_version_id=active.id, comment=str((payload or {}).get("comment") or "Authentication policy taken from the collected posture"), golden_authentication_policy=posture)
            source.active_version_id = version.id
            repo.upsert("golden_sources", source)
            repo.upsert("golden_source_versions", version)
            record_audit(repo, request, "golden_source.authentication_policy_set", "golden_source_version", version.id, {"source_id": source.id, "version": version.version})
            return {"version": version.version, "version_id": version.id, "controls": len(posture.controls)}

    @app.get("/api/golden-sources/{name}/accesses")
    def golden_accesses(name: str, request: Request, search: str | None = None, limit: int = 25, offset: int = 0, sort: str | None = None, order: str | None = None):
        """The expected accesses themselves: each role or group, what it allows, and how many people hold it."""
        from access_review_engine.web_read_models import _display_names, sorted_rows

        _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            source, versions, active = _golden_context(repo, name)
            if active is None:
                raise HTTPException(status_code=409, detail="Golden Source has no version yet")
            identity_names, access_names = _display_names(repo)
            catalog = {(str(row.get("provider")), str(row.get("name"))): row for row in repo.list_payloads("accesses")}
            grouped: dict[tuple[str, str], dict[str, Any]] = {}
            for item in active.assignments:
                key = (item.access_provider, item.access_name)
                row = grouped.get(key)
                if row is None:
                    described = catalog.get(key, {})
                    permission = described.get("permission")
                    row = grouped[key] = {
                        "access_provider": item.access_provider,
                        "access_name": item.access_name,
                        "access_display_name": access_names.get(key) or item.access_name,
                        "access_description": described.get("description"),
                        "access_target": described.get("target"),
                        "access_owner": (described.get("access_owner") or {}).get("identity") if isinstance(described.get("access_owner"), dict) else None,
                        "access_permission": item.access_permission or ((permission or {}).get("display_name") or (permission or {}).get("identifier") if isinstance(permission, dict) else permission),
                        "expected_identities": 0,
                        "identities": [],
                    }
                row["expected_identities"] += 1
                row["identities"].append({
                    "identity_provider": item.identity_provider,
                    "identity_identifier": item.identity_identifier,
                    "identity_display_name": identity_names.get((item.identity_provider, item.identity_identifier)) or item.identity_identifier,
                })
            rows = sorted(grouped.values(), key=lambda row: str(row["access_display_name"]).casefold())
            for row in rows:
                row["identities"].sort(key=lambda entry: str(entry["identity_display_name"]).casefold())
            if search:
                needle = search.casefold()
                rows = [row for row in rows if needle in " ".join(str(row.get(field) or "") for field in ("access_display_name", "access_name", "access_description", "access_provider", "access_permission")).casefold()]
            if sort:
                rows = sorted_rows(rows, sort, order)
            bounded, start = max(1, min(limit, 500)), max(0, offset)
            return {"items": rows[start : start + bounded], "total": len(rows), "limit": bounded, "offset": start, "version": active.version, "sort": sort or "", "order": (order or "asc").lower()}

    @app.post("/api/golden-sources/{name}/assignments")
    def golden_edit_assignments(name: str, request: Request, payload: dict[str, Any] = Body(...)):
        """Add, remove or replace expected assignments, as a new immutable version."""
        from access_review_engine.domain import GoldenSourceAssignment

        _require(current_user(request), ("ADMIN", "OPERATOR"))

        def entry(row: Any) -> GoldenSourceAssignment:
            if not isinstance(row, dict):
                raise HTTPException(status_code=400, detail="Each expected access must be an object")
            missing = [key for key in ("access_provider", "access_name", "identity_provider", "identity_identifier") if not str(row.get(key, "")).strip()]
            if missing:
                raise HTTPException(status_code=400, detail="Expected access requires " + ", ".join(missing))
            return GoldenSourceAssignment(
                access_provider=str(row["access_provider"]).strip(),
                access_name=str(row["access_name"]).strip(),
                identity_provider=str(row["identity_provider"]).strip(),
                identity_identifier=str(row["identity_identifier"]).strip(),
                access_native_id=str(row.get("access_native_id") or "") or None,
                access_permission=str(row.get("access_permission") or "") or None,
                identity_native_id=str(row.get("identity_native_id") or "") or None,
            )

        with Repository(db_path) as repo:
            source, versions, active = _golden_context(repo, name)
            replace = payload.get("replace")
            if replace is not None:
                assignments = {entry(row) for row in replace}
                origin, comment = "csv", str(payload.get("comment") or "Replaced from the WebUI")
            else:
                assignments = set(active.assignments) if active else set()
                assignments |= {entry(row) for row in payload.get("add", [])}
                assignments -= {entry(row) for row in payload.get("remove", [])}
                origin, comment = "manual", str(payload.get("comment") or "Edited in the WebUI")
            if active is not None and assignments == set(active.assignments):
                raise HTTPException(status_code=409, detail="This change leaves the Golden Source unchanged")
            try:
                version = create_golden_version(source, assignments, origin, versions, parent_version_id=active.id if active else None, comment=comment, golden_authentication_policy=active.golden_authentication_policy if active else None)
            except ValueError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            source.active_version_id = version.id
            repo.upsert("golden_sources", source)
            repo.upsert("golden_source_versions", version)
            record_audit(repo, request, "golden_source.version_edited", "golden_source_version", version.id, {"source_id": source.id, "version": version.version, "assignments": len(version.assignments)})
            return {"version": version.version, "version_id": version.id, "assignments": len(version.assignments)}

    @app.get("/api/golden-sources/{name}/export")
    def export_baseline(name: str, request: Request):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            source = repo.find_by_name("golden_sources", name)
            if not source:
                raise HTTPException(status_code=404, detail="Golden Source not found")
            golden = hydrate_golden_source(source)
            versions = [hydrate_golden_version(row) for row in repo.list_payloads("golden_source_versions") if row.get("golden_source_id") == golden.id]
            if not versions:
                raise HTTPException(status_code=409, detail="Golden Source has no version")
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=["access_provider", "access_name", "identity_provider", "identity_identifier", "permission"])
            writer.writeheader()
            for item in versions[-1].assignments:
                writer.writerow({"access_provider": item.access_provider, "access_name": item.access_name, "identity_provider": item.identity_provider, "identity_identifier": item.identity_identifier, "permission": item.access_permission or ""})
            return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename={name}-baseline.csv"})


    @app.get("/api/reports/{campaign_id}/results")
    def campaign_report_results(campaign_id: str, request: Request, search: str | None = None, classification: str | None = None, decision: str | None = None, provider: str | None = None, owner: str | None = None, limit: int = 25, offset: int = 0, sort: str | None = None, order: str | None = None):
        """The report, readable in the WebUI: same rows and same counts as the exported file."""
        from access_review_engine.web_read_models import sorted_rows

        _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            raw = repo.get_payload("campaigns", campaign_id)
            if raw is None:
                raise HTTPException(status_code=404, detail="Campaign not found")
            campaign = hydrate_campaign(raw)
            items = [hydrate_review_item(row) for row in repo.list_payloads("review_items") if row.get("campaign_id") == campaign_id]
            decisions = [hydrate_decision(row) for row in repo.list_payloads("decisions") if row.get("review_item_id") in {item.id for item in items}]
        rows = build_report_rows(items, decisions)
        summary = report_summary(rows)
        facets = {
            "classification": sorted({str(row["classification"]) for row in rows if row["classification"]}),
            "decision": sorted({str(row["decision"]) for row in rows if row["decision"]}),
            "provider": sorted({str(row["provider"]) for row in rows if row["provider"]}),
            "owner": sorted({str(row["owner"]) for row in rows if row["owner"]}),
        }
        selected = {"classification": classification, "decision": decision, "provider": provider, "owner": owner}
        for field, value in selected.items():
            if value:
                rows = [row for row in rows if str(row.get(field)) == value]
        if search:
            needle = search.casefold()
            rows = [row for row in rows if needle in " ".join(str(value) for value in row.values()).casefold()]
        if sort:
            rows = sorted_rows(rows, sort, order)
        bounded, start = max(1, min(limit, 500)), max(0, offset)
        return {
            "campaign": {"id": campaign.id, "name": campaign.name, "status": campaign.status, "due_at": campaign.due_at, "opened_at": campaign.opened_at, "closed_at": campaign.closed_at, "snapshot_id": campaign.snapshot_id, "golden_source_version_id": campaign.golden_source_version_id},
            "summary": summary,
            "facets": facets,
            "items": rows[start : start + bounded],
            "total": len(rows),
            "limit": bounded,
            "offset": start,
            "sort": sort or "",
            "order": (order or "asc").lower(),
        }

    @app.get("/api/reports/{campaign_id}/{format}")
    def campaign_report(campaign_id: str, format: str, request: Request):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        if format not in {"html", "csv", "json"}:
            raise HTTPException(status_code=404, detail="Report format not available")
        with Repository(db_path) as repo:
            raw = repo.get_payload("campaigns", campaign_id)
            if raw is None:
                raise HTTPException(status_code=404, detail="Campaign not found")
            campaign = hydrate_campaign(raw)
            items = [hydrate_review_item(row) for row in repo.list_payloads("review_items") if row.get("campaign_id") == campaign_id]
            decisions = [hydrate_decision(row) for row in repo.list_payloads("decisions") if row.get("review_item_id") in {item.id for item in items}]
            golden = _golden_version(repo, campaign.golden_source_version_id)
            snapshot = _snapshot(repo, campaign.snapshot_id)
            with tempfile.TemporaryDirectory(prefix="eare-report-") as directory:
                write_reports(directory, campaign, items, decisions, golden, snapshot.authentication_posture)
                filename = {"html": "campaign-report.html", "csv": "campaign-results.csv", "json": "campaign-results.json"}[format]
                content = (Path(directory) / filename).read_bytes()
            media = {"html": "text/html", "csv": "text/csv", "json": "application/json"}[format]
            safe_campaign_id = "".join(character if character.isalnum() or character in "-_" else "_" for character in campaign_id)
            return StreamingResponse(iter([content]), media_type=media, headers={"Content-Disposition": f"attachment; filename={safe_campaign_id}-{filename}"})

    @app.get("/api/dashboard")
    def dashboard(request: Request):
        """What deserves attention today, and what to do about it."""
        principal = _require(current_user(request), ("ADMIN", "OPERATOR"))
        today = time.strftime("%Y-%m-%d")
        with Repository(db_path) as repo:
            campaigns = repo.list_payloads("campaigns")
            items = repo.list_payloads("review_items")
            decided = {str(row.get("review_item_id")) for row in repo.list_payloads("decisions")}
            actions = repo.list_payloads("remediation_actions")
            snapshots = repo.list_payloads("snapshots")
            sources = repo.list_payloads("golden_sources")
            versions = repo.list_payloads("golden_source_versions")
            connectors = repo.list_payloads("providers")
        snapshot = snapshots[-1] if snapshots else None
        comparison = list(snapshot.get("comparison_states", [])) if snapshot else []
        pending_actions = [row for row in actions if row.get("status") != "exported"]
        open_campaigns = [row for row in campaigns if row.get("status") == "open"]
        providers = projected_rows(db_path, "providers", limit=100, offset=0)["items"]
        attention: list[dict[str, Any]] = []

        def note(tone: str, title: str, detail: str, link: str) -> None:
            attention.append({"tone": tone, "title": title, "detail": detail, "link": link})

        for row in providers:
            if row.get("health") == "failed":
                note("red", f"Collection failed on {row.get('name')}", "The last synchronization did not complete.", "/sources")
            elif row.get("health") == "never_synced":
                note("amber", f"{row.get('name')} has never been collected", "EARE knows nothing about this source yet.", "/sources")
        if not connectors:
            note("blue", "No source yet", "Connect the first directory or application EARE should audit.", "/sources")
        elif not snapshot:
            note("blue", "Nothing collected yet", "Synchronize a source to see identities and accesses.", "/sources")

        active_versions = {str(row.get("active_version_id")) for row in sources}
        active = [row for row in versions if str(row.get("id")) in active_versions]
        newest_expected = max((str(row.get("created_at", "")) for row in active), default="")
        if not sources:
            note("blue", "No expected state yet", "Declare what is expected, so deviations can be reported.", "/golden")
        elif snapshot and newest_expected and str(snapshot.get("created_at", "")) > newest_expected:
            note("amber", "The systems changed since the expected state was set", "Compare the collected state with the Golden Source.", "/golden")

        for row in open_campaigns:
            scoped = [item for item in items if item.get("campaign_id") == row.get("id")]
            waiting = [item for item in scoped if str(item.get("id")) not in decided]
            due = str(row.get("due_at") or "")
            if waiting and due and due < today:
                note("red", f"{row.get('name')} is overdue", f"{len(waiting)} review(s) still waiting, due {due}.", f"/campaigns/{row.get('id')}")
            elif waiting:
                note("amber", f"{row.get('name')} is in progress", f"{len(waiting)} review(s) still waiting.", f"/campaigns/{row.get('id')}")
            else:
                note("blue", f"{row.get('name')} can be closed", "Every review has been decided.", f"/campaigns/{row.get('id')}")
        promoted = {str(row.get("source_campaign_id")) for row in versions if row.get("source_campaign_id")}
        for row in campaigns:
            if row.get("status") == "closed" and str(row.get("id")) not in promoted:
                note("blue", f"{row.get('name')} is closed but not promoted", "Its decisions have not been carried into the expected state.", f"/campaigns/{row.get('id')}")
        if pending_actions:
            note("amber", f"{len(pending_actions)} remediation action(s) to carry out", "Decisions are waiting to be applied in the systems.", "/actions")
        if not campaigns and snapshot:
            note("blue", "No campaign yet", "A campaign asks the owners to confirm who should keep their access.", "/campaigns/new")

        return {
            "role": principal.role,
            "metrics": {
                "campaigns": len(open_campaigns),
                "pending_reviews": sum(1 for item in items if str(item.get("id")) not in decided and item.get("campaign_id") in {str(row.get("id")) for row in open_campaigns}),
                "remediation_actions": len(pending_actions),
                "findings": sum(1 for row in comparison if row.get("findings")),
            },
            "collected_at": snapshot.get("created_at") if snapshot else None,
            "collected_from": [provider.get("name") for provider in (snapshot or {}).get("providers", [])],
            "expected_state": {"name": sources[0].get("name"), "version": max((int(row.get("version", 0)) for row in active), default=0), "assignments": max((len(row.get("assignments", [])) for row in active), default=0)} if sources else None,
            "campaigns": [
                {"id": row.get("id"), "name": row.get("name"), "status": row.get("status"), "due_at": row.get("due_at"), "review_items": len([item for item in items if item.get("campaign_id") == row.get("id")]), "pending": len([item for item in items if item.get("campaign_id") == row.get("id") and str(item.get("id")) not in decided])}
                for row in open_campaigns[:4]
            ],
            "sources": [{"name": row.get("name"), "health": row.get("health"), "last_sync": row.get("last_sync"), "identity_count": row.get("identity_count"), "access_count": row.get("access_count")} for row in providers],
            "attention": attention[:8],
        }


    def _snapshot(repo: Repository, snapshot_id: str | None = None):
        snapshots = repo.list_payloads("snapshots")
        payload = next((row for row in snapshots if row.get("id") == snapshot_id), None) if snapshot_id else (snapshots[-1] if snapshots else None)
        if payload is None:
            raise HTTPException(status_code=404, detail="Snapshot not found")
        return hydrate_snapshot(payload)

    def _golden_version(repo: Repository, version_id: str | None):
        if not version_id:
            return None
        payload = next((row for row in repo.list_payloads("golden_source_versions") if row.get("id") == version_id), None)
        if payload is None:
            raise HTTPException(status_code=404, detail="Golden Source version not found")
        return hydrate_golden_version(payload)

    def _campaign_payload(payload: dict[str, Any], *, draft_id: str | None = None):
        from access_review_engine.domain import Campaign, OwnerRef
        def owner(value: Any):
            if value is None:
                return None
            if not isinstance(value, dict) or not value.get("provider") or not value.get("identity"):
                raise HTTPException(status_code=400, detail="Reviewer references require provider and identity")
            return OwnerRef(provider=str(value["provider"]), identity=str(value["identity"]))
        allowed = {key: payload[key] for key in ("name", "snapshot_id", "display_name", "description", "golden_source_version_id", "scope", "allow_unresolved_reviewers", "due_at") if key in payload}
        allowed["name"] = str(allowed.get("name") or "").strip()
        if not allowed["name"] or not isinstance(allowed.get("snapshot_id"), str) or not allowed["snapshot_id"].strip():
            raise HTTPException(status_code=400, detail="Campaign name and snapshot_id are required")
        allowed["snapshot_id"] = allowed["snapshot_id"].strip()
        allowed["scope"] = allowed.get("scope") or {"type": "all"}
        if not isinstance(allowed["scope"], dict) or allowed["scope"].get("type") not in {"all", "providers"}:
            raise HTTPException(status_code=400, detail="Campaign scope must be all or providers")
        allowed["default_reviewer"] = owner(payload.get("default_reviewer"))
        allowed["manager"] = owner(payload.get("manager"))
        if draft_id:
            allowed["id"] = draft_id
        return Campaign(**allowed)

    @app.post("/api/campaigns/preview")
    def campaign_preview(request: Request, payload: dict[str, Any] = Body(...)):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        campaign = _campaign_payload(payload)
        with Repository(db_path) as repo:
            snapshot = _snapshot(repo, campaign.snapshot_id)
            golden = _golden_version(repo, campaign.golden_source_version_id)
            return preview_campaign_review(campaign, snapshot, golden)

    @app.post("/api/campaigns")
    def campaign_create(request: Request, payload: dict[str, Any] = Body(...)):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        campaign = _campaign_payload(payload)
        with Repository(db_path) as repo:
            _snapshot(repo, campaign.snapshot_id)
            repo.upsert("campaigns", campaign)
            record_audit(repo, request, "campaign.created", "campaign", campaign.id, {"snapshot_id": campaign.snapshot_id})
        return asdict(campaign)

    @app.post("/api/campaigns/{campaign_id}/open")
    def campaign_open(campaign_id: str, request: Request, payload: dict[str, Any] | None = Body(default=None)):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            raw = repo.get_payload("campaigns", campaign_id)
            if raw is None:
                raise HTTPException(status_code=404, detail="Campaign not found")
            campaign = hydrate_campaign(raw)
            if payload and "allow_unresolved_reviewers" in payload:
                campaign.allow_unresolved_reviewers = bool(payload["allow_unresolved_reviewers"])
            snapshot = _snapshot(repo, campaign.snapshot_id)
            golden = _golden_version(repo, campaign.golden_source_version_id)
            try:
                preparation = prepare_campaign_review(campaign, snapshot, golden)
                opened, items = open_campaign(campaign, preparation.snapshot)
            except ValueError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            repo.upsert("campaigns", opened)
            for item in items:
                repo.upsert("review_items", item)
            record_audit(repo, request, "campaign.opened", "campaign", opened.id, {"review_items": len(items)})
            return {"campaign": asdict(opened), "items": len(items)}

    @app.post("/api/campaigns/{campaign_id}/close")
    def campaign_close(campaign_id: str, request: Request):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            raw = repo.get_payload("campaigns", campaign_id)
            if raw is None:
                raise HTTPException(status_code=404, detail="Campaign not found")
            campaign = hydrate_campaign(raw)
            if campaign.status != "open":
                raise HTTPException(status_code=409, detail="Only open campaigns can be closed")
            items = [hydrate_review_item(row) for row in repo.list_payloads("review_items") if row.get("campaign_id") == campaign_id]
            decisions = [hydrate_decision(row) for row in repo.list_payloads("decisions") if row.get("review_item_id") in {item.id for item in items}]
            try:
                closed = close_campaign(campaign, items, decisions)
            except ValueError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            repo.upsert("campaigns", closed)
            # Closing is what turns decisions into work for the people who operate the systems.
            actions = remediation_from_decisions(items, decisions)
            for action in actions:
                repo.insert_append_only("remediation_actions", action)
            record_audit(repo, request, "campaign.closed", "campaign", closed.id, {"review_items": len(items), "remediation_actions": len(actions)})
            return {**asdict(closed), "remediation_actions": len(actions)}

    @app.post("/api/campaigns/{campaign_id}/cancel")
    def campaign_cancel(campaign_id: str, request: Request):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            raw = repo.get_payload("campaigns", campaign_id)
            if raw is None:
                raise HTTPException(status_code=404, detail="Campaign not found")
            campaign = hydrate_campaign(raw)
            if campaign.status != "draft":
                raise HTTPException(status_code=409, detail="Only draft campaigns can be cancelled")
            campaign.status = "cancelled"
            repo.upsert("campaigns", campaign)
            record_audit(repo, request, "campaign.cancelled", "campaign", campaign.id)
            return asdict(campaign)

    @app.post("/api/campaigns/{campaign_id}/promote")
    def campaign_promote(campaign_id: str, request: Request):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            raw = repo.get_payload("campaigns", campaign_id)
            if raw is None:
                raise HTTPException(status_code=404, detail="Campaign not found")
            campaign = hydrate_campaign(raw)
            if campaign.status != "closed":
                raise HTTPException(status_code=409, detail="Only closed campaigns can be promoted")
            source_payloads = repo.list_payloads("golden_sources")
            if not source_payloads:
                raise HTTPException(status_code=409, detail="A Golden Source is required")
            version_payloads = repo.list_payloads("golden_source_versions")
            selected_version = next((row for row in version_payloads if row.get("id") == campaign.golden_source_version_id), None)
            if selected_version is None:
                raise HTTPException(status_code=409, detail="Campaign has no unambiguous Golden Source reference.")
            source_payload = next(
                (row for row in source_payloads if row.get("id") == selected_version.get("golden_source_id")),
                None,
            )
            if source_payload is None:
                raise HTTPException(status_code=409, detail="Campaign Golden Source reference is invalid.")
            source = hydrate_golden_source(source_payload)
            versions = [hydrate_golden_version(row) for row in version_payloads if row.get("golden_source_id") == source.id]
            previous = max(versions, key=lambda item: item.version) if versions else None
            items = [hydrate_review_item(row) for row in repo.list_payloads("review_items") if row.get("campaign_id") == campaign_id]
            decisions = [hydrate_decision(row) for row in repo.list_payloads("decisions") if row.get("review_item_id") in {item.id for item in items}]
            try:
                version = promote_campaign(source, campaign, items, decisions, previous, mode="replace_scope")
            except ValueError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            # Promotion changes who is expected to have what, not how people authenticate.
            if version.golden_authentication_policy is None and previous is not None:
                version.golden_authentication_policy = previous.golden_authentication_policy
            source.active_version_id = version.id
            repo.upsert("golden_sources", source)
            repo.upsert("golden_source_versions", version)
            record_audit(repo, request, "campaign.promoted", "campaign", campaign.id, {"version_id": version.id, "golden_source_id": source.id})
            return {"source": asdict(source), "version": asdict(version)}

    @app.get("/api/campaigns/{campaign_id}")
    def campaign_detail(campaign_id: str, request: Request):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        result = page("campaigns", 500, 0, None, None, None)
        campaign = next((item for item in result["items"] if item.get("id") == campaign_id), None)
        if campaign is None:
            raise HTTPException(status_code=404, detail="Campaign not found")
        reviews = [item for item in page("review_items", 500, 0, None, None, None)["items"] if item.get("campaign_id") == campaign_id]
        findings = [finding for item in reviews for finding in item.get("findings", [])]
        return {"campaign": campaign, "reviews": reviews, "findings": sorted(set(findings))}

    @app.get("/api/audit-events")
    def audit_events(request: Request, limit: int = 100, offset: int = 0):
        _require(current_user(request), ("ADMIN",))
        bounded_limit = max(1, min(limit, 500))
        bounded_offset = max(0, offset)
        with Repository(db_path) as repo:
            events = repo.list_payloads("audit_events")
        return {"items": events[bounded_offset : bounded_offset + bounded_limit], "total": len(events), "limit": bounded_limit, "offset": bounded_offset}

    tables = {"providers": "providers", "imports": "imports", "identities": "identities", "accesses": "accesses", "assignments": "access_assignments", "golden-sources": "golden_sources", "golden-source-versions": "golden_source_versions", "snapshots": "snapshots", "campaigns": "campaigns", "review-items": "review_items", "decisions": "decisions", "remediation-actions": "remediation_actions"}
    for path, table in tables.items():
        def route(request: Request, limit: int = 100, offset: int = 0, search: str | None = None, status: str | None = None, provider: str | None = None, campaign: str | None = None, sort: str | None = None, order: str | None = None, _table: str = table):
            principal = _require(current_user(request))
            require_table_access(principal, _table)
            return scoped_page(principal, _table, limit, offset, search, status, provider, campaign, sort, order)
        app.get(f"/api/{path}")(route)

    @app.get("/api/findings")
    def findings(request: Request, limit: int = 100, offset: int = 0, search: str | None = None, status: str | None = None, provider: str | None = None, campaign: str | None = None, sort: str | None = None, order: str | None = None):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        snapshot = latest_snapshot(db_path) or {}
        rows = list(snapshot.get("comparison_states", []))
        if campaign:
            with Repository(db_path) as repo:
                campaign_keys = {
                    (
                        item.get("access_provider"),
                        item.get("access_name"),
                        item.get("identity_provider"),
                        item.get("identity_identifier"),
                    )
                    for item in repo.list_payloads("review_items")
                    if item.get("campaign_id") == campaign
                }
                rows = [
                    row for row in rows
                    if (
                        row.get("access_provider"),
                        row.get("access_name"),
                        row.get("identity_provider"),
                        row.get("identity_identifier"),
                    ) in campaign_keys
                ]
        if status:
            rows = [row for row in rows if row.get("classification") == status]
        if provider:
            rows = [row for row in rows if row.get("access_provider") == provider]
        if search:
            needle = search.casefold()
            rows = [row for row in rows if needle in json.dumps(row, sort_keys=True).casefold()]
        if sort:
            from access_review_engine.web_read_models import sorted_rows

            rows = sorted_rows(rows, sort, order)
        return {"items": rows[offset : offset + limit], "total": len(rows), "limit": limit, "offset": offset, "sort": sort or "", "order": (order or "asc").lower()}

    @app.get("/api/identities/{identity_id}/accesses")
    def identity_accesses(identity_id: str, request: Request):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        snapshot = latest_snapshot(db_path) or {}
        identities = {f"{item.get('provider')}:{item.get('identifier')}": item for item in snapshot.get("identities", [])}
        identity = next((item for item in snapshot.get("identities", []) if item.get("id") == identity_id), None)
        if identity is None:
            identity = next((item for item in snapshot.get("identities", []) if item.get("identifier") == identity_id), None)
        if identity is None:
            raise HTTPException(status_code=404, detail="Identity not found")
        assignments = [row for row in snapshot.get("access_assignments", []) if row.get("identity_provider") == identity.get("provider") and row.get("identity_identifier") == identity.get("identifier")]
        hydrated = hydrate_snapshot(snapshot)
        evaluation = calculate_effective_accesses(hydrated.access_assignments, hydrated.access_relations, hydrated.accesses)
        effective = [asdict(item) for item in evaluation.effective_accesses if item.identity_provider == identity.get("provider") and item.identity_identifier == identity.get("identifier")]
        return {"identity": identity, "accesses": assignments, "effective_accesses": effective, "paths": [path for item in effective for path in item.get("paths", [])]}

    @app.get("/api/accesses/{provider}/{access_name}/holders")
    def access_holders(provider: str, access_name: str, request: Request):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        snapshot = latest_snapshot(db_path) or {}
        rows = [row for row in snapshot.get("access_assignments", []) if row.get("provider") == provider and row.get("access_name") == access_name]
        hydrated = hydrate_snapshot(snapshot)
        evaluation = calculate_effective_accesses(hydrated.access_assignments, hydrated.access_relations, hydrated.accesses)
        effective = [asdict(item) for item in evaluation.effective_accesses if item.access_provider == provider and item.access_name == access_name]
        return {"access": {"provider": provider, "name": access_name}, "holders": rows, "effective_holders": effective, "paths": [path for item in effective for path in item.get("paths", [])]}

    @app.post("/api/sources/{provider}/sync", status_code=202)
    def sync(provider: str, request: Request):
        _require(current_user(request), ("ADMIN", "OPERATOR"), provider)
        def operation(job_id: str) -> dict[str, Any]:
            config = _load_web_connector(provider)
            secrets_config = secret_environment(config)
            if secrets_config.get("password_file"):
                config.setdefault("credentials", {})["password_file"] = secrets_config["password_file"]
            artifact = Path(db_path).with_name(f".eare-{provider}-{job_id}.zip")
            try:
                update_progress(db_path, job_id, "Collecting read-only source data")
                result = run_exporter(config, artifact)
                if result.returncode:
                    raise RunnerError(result.stderr.strip() or "Collector failed")
                update_progress(db_path, job_id, "Importing and creating snapshot")
                with Repository(db_path) as repo:
                    snapshot = import_file_to_repository(repo, artifact, provider_name=provider)
                    record_audit(repo, request, "source.sync_completed", "snapshot", snapshot.id, {"provider": provider})
                return {"snapshot_id": snapshot.id, "provider": provider}
            finally:
                artifact.unlink(missing_ok=True)
        return create_job(db_path, "sync", operation)

    @app.post("/api/sources/{provider}/preview", status_code=202)
    def source_preview(provider: str, request: Request):
        _require(current_user(request), ("ADMIN", "OPERATOR"), provider)
        def operation(job_id: str) -> dict[str, Any]:
            artifact = Path(db_path).with_name(f".eare-preview-{provider}-{job_id}.zip")
            try:
                update_progress(db_path, job_id, "Collecting read-only source data")
                config = _load_web_connector(provider)
                secrets_config = secret_environment(config)
                if secrets_config.get("password_file"):
                    config.setdefault("credentials", {})["password_file"] = secrets_config["password_file"]
                result = run_exporter(config, artifact)
                if result.returncode:
                    raise RunnerError(result.stderr.strip() or "Collector failed")
                update_progress(db_path, job_id, "Analysing collected data")
                preview = preview_import(db_path, artifact, provider=provider).as_dict()
                with Repository(db_path) as repo:
                    record_audit(repo, request, "source.preview_completed", "provider", provider)
                return preview
            finally:
                artifact.unlink(missing_ok=True)
        return create_job(db_path, "preview", operation)

    @app.post("/api/sources/{provider}/sync/preview")
    def sync_preview(provider: str, request: Request, input_path: str, classification_rules: str | None = None):
        _require(current_user(request), ("ADMIN", "OPERATOR"), provider)
        return preview_import(db_path, input_path, provider=provider, classification_rules=classification_rules).as_dict()

    @app.get("/api/jobs/{job_id}")
    def job(job_id: str, request: Request):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        try:
            return get_job(db_path, job_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Job not found") from exc

    @app.get("/api/jobs/{job_id}/events")
    def job_events(job_id: str, request: Request):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        try:
            get_job(db_path, job_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Job not found") from exc
        body = "".join(f"event: {event['event']}\ndata: {json.dumps(event)}\n\n" for event in get_events(db_path, job_id))
        return StreamingResponse(iter([body]), media_type="text/event-stream")

    @app.post("/api/review-items/{review_item_id}/decision")
    def decision(review_item_id: str, request: Request, body: dict[str, Any] = Body(...)):
        principal = _require(current_user(request), ("ADMIN", "OPERATOR", "GROUP_OWNER"))
        with Repository(db_path) as repo:
            item_payload = repo.get_payload("review_items", review_item_id)
            if item_payload is None:
                raise HTTPException(status_code=404, detail="Review item not found")
            item = hydrate_review_item(item_payload)
            campaign_payload = repo.get_payload("campaigns", item_payload.get("campaign_id"))
            if campaign_payload is None:
                raise HTTPException(status_code=409, detail="Review item campaign is missing")
            if hydrate_campaign(campaign_payload).status != "open":
                raise HTTPException(status_code=409, detail="Decisions are only allowed for open campaigns")
            if principal.role == "GROUP_OWNER" and (item.reviewer is None or item.reviewer.identity != principal.username):
                raise HTTPException(status_code=403, detail="Review item is not assigned to this user")
            value = body.get("value")
            comment = body.get("comment")
            if not isinstance(value, str) or (comment is not None and not isinstance(comment, str)):
                raise HTTPException(status_code=400, detail="A decision value and optional comment are required")
            try:
                result = create_decision(item, value, comment, principal.subject)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            repo.insert_append_only("decisions", result)
            record_audit(repo, request, "review.decision_recorded", "review_item", item.id, {"decision": result.value})
        return asdict(result)

    return app
